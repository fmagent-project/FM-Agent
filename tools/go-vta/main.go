package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/format"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/callgraph/vta"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

type location struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
}

type function struct {
	ID      int      `json:"id"`
	At      location `json:"at"`
	Owner   location `json:"owner"`
	Closure bool     `json:"closure"`
}

type edge struct {
	Caller int      `json:"caller"`
	Callee int      `json:"callee"`
	At     location `json:"at"`
	Labels []string `json:"labels"`
}

type result struct {
	Files     []string   `json:"files"`
	Functions []function `json:"functions"`
	Edges     []edge     `json:"edges"`
}

func run() error {
	if len(os.Args) < 3 {
		return fmt.Errorf("usage: go-vta MODULE_DIR PROJECT_ROOT [PACKAGE ...]")
	}
	projectRoot, err := filepath.Abs(os.Args[2])
	if err != nil {
		return err
	}
	patterns := os.Args[3:]
	if len(patterns) == 0 {
		patterns = []string{"./..."}
	}
	fset := token.NewFileSet()
	loaded, err := packages.Load(&packages.Config{
		Dir: os.Args[1], Mode: packages.LoadAllSyntax, Fset: fset, Tests: true,
	}, patterns...)
	if err != nil {
		return err
	}
	if packages.PrintErrors(loaded) != 0 || len(loaded) == 0 {
		return fmt.Errorf("Go module did not load")
	}
	output := result{Files: []string{}, Functions: []function{}, Edges: []edge{}}
	files := make(map[string]bool)
	callPositions := make(map[token.Pos]token.Pos)
	callLabels := make(map[token.Pos]string)
	packages.Visit(loaded, func(pkg *packages.Package) bool {
		for _, file := range pkg.CompiledGoFiles {
			relative, err := filepath.Rel(projectRoot, file)
			if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
				files[file] = true
			}
		}
		for _, syntax := range pkg.Syntax {
			if !files[fset.PositionFor(syntax.Pos(), false).Filename] {
				continue
			}
			ast.Inspect(syntax, func(node ast.Node) bool {
				if call, ok := node.(*ast.CallExpr); ok {
					callPositions[call.Lparen] = call.Fun.Pos()
					var label bytes.Buffer
					if format.Node(&label, fset, call.Fun) == nil {
						callLabels[call.Lparen] = label.String()
					}
				}
				return true
			})
		}
		return true
	}, nil)
	for file := range files {
		output.Files = append(output.Files, file)
	}
	sort.Strings(output.Files)
	program, _ := ssautil.AllPackages(loaded, ssa.InstantiateGenerics)
	program.Build()
	graph := vta.CallGraph(ssautil.AllFunctions(program), cha.CallGraph(program))
	locate := func(pos token.Pos) location {
		at := fset.PositionFor(pos, false)
		return location{at.Filename, at.Line, at.Column}
	}
	ids := make(map[*ssa.Function]int)
	for fn := range graph.Nodes {
		if fn == nil {
			continue
		}
		origin := fn.Origin()
		if origin == nil {
			origin = fn
		}
		owner := origin
		for owner.Parent() != nil {
			owner = owner.Parent()
		}
		position := owner.Pos()
		if owner.Object() != nil {
			position = owner.Object().Pos()
		}
		at := locate(position)
		if !files[at.File] || at.Line == 0 {
			continue
		}
		id := len(output.Functions)
		ids[fn] = id
		output.Functions = append(output.Functions, function{
			ID: id, At: locate(origin.Pos()), Owner: at, Closure: origin.Parent() != nil,
		})
	}
	for fn, callerID := range ids {
		for _, call := range graph.Nodes[fn].Out {
			calleeID, found := ids[call.Callee.Func]
			if !found || call.Site == nil {
				continue
			}
			position := call.Site.Common().Pos()
			labels := []string{}
			if label := callLabels[position]; label != "" {
				labels = append(labels, label)
			}
			if common := call.Site.Common(); common.IsInvoke() {
				receiver := types.TypeString(common.Value.Type(), func(*types.Package) string { return "" })
				labels = append(labels, receiver+"."+common.Method.Name())
			}
			if start, found := callPositions[position]; found {
				position = start
			}
			at := locate(position)
			if !files[at.File] {
				at = location{File: output.Functions[callerID].Owner.File}
			}
			output.Edges = append(output.Edges, edge{callerID, calleeID, at, labels})
		}
	}
	return json.NewEncoder(os.Stdout).Encode(output)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
