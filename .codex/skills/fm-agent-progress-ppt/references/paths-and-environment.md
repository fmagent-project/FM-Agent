# Paths and environment

Verify every path before use. These are the paths observed on 2026-07-27.

## Project and evidence

- Workspace root: `D:\fmagent`
- FM-Agent repository: `D:\fmagent\FM-Agent`
- Repository guidance: `D:\fmagent\agent.md`
- Pluginization plan deck: `D:\fmagent\docs\插件化方案.pptx`
- Meeting template used for the 7.27 report:
  `D:\fmagent\ppt\7.27\FM-Agent例会PPT模版.pptx`
- Output directory used for the 7.27 report: `D:\fmagent\ppt\7.27`
- Local memory/notes:
  - `D:\fmagent\experience.MD`
  - `D:\fmagent\plan.md`
  - `D:\fmagent\FM-Agent 内部开发规范.md`
  - `D:\fmagent\sidecar.patch`
  - repository `README.md`, `README_zh.md`, `docs\`, `.agents\`, `.codex\`
- Prior report scratch:
  `D:\fmagent\ppt\7.27\.codex-work\fmagent-weekly-report`

For another date, search rather than reusing `7.27` blindly:

```powershell
rg --files D:\fmagent\ppt D:\fmagent\docs |
  rg "例会|模版|模板|插件化方案|\.pptx$"
```

## GitHub repositories and remotes

- Public repository: `fmagent-project/FM-Agent`
- Private repository: `fmagent-project/FM-Agent-Internal`
- Local remote `public`: public repository
- Local remote `private`: internal repository

Public PRs/issues must be read from `fmagent-project/FM-Agent`. Development
branches may exist only or first on `private`.

## Presentation skill and runtime

The presentation skill is versioned. Locate the newest available path instead
of assuming the version below:

```powershell
Get-ChildItem C:\Users\Joy\.codex\plugins\cache\openai-primary-runtime\presentations `
  -Recurse -Filter SKILL.md |
  Where-Object FullName -like '*\skills\presentations\SKILL.md'
```

Path used on 2026-07-27:

`C:\Users\Joy\.codex\plugins\cache\openai-primary-runtime\presentations\26.709.11516\skills\presentations\SKILL.md`

The working `@oai/artifact-tool` package was found at:

`C:\Users\Joy\AppData\Local\Temp\codex-presentations\artifact-tool-smoke\node_modules\@oai\artifact-tool`

The presentation helper derived its runtime from `HOME` and incorrectly looked
under:

`D:\fmagent\.cache\codex-runtimes\codex-primary-runtime\dependencies\node\node_modules\@oai\artifact-tool`

If setup reports a missing package:

1. Search for the real package:

   ```powershell
   Get-ChildItem C:\Users\Joy\AppData\Local\Temp,C:\Users\Joy\.codex,D:\Apps `
     -Recurse -Filter package.json -ErrorAction SilentlyContinue |
     Where-Object FullName -like '*artifact-tool*'
   ```

2. Verify its `package.json` names `@oai/artifact-tool`.
3. Prefer pointing the helper to the real runtime. If the helper has no runtime
   option, create a narrow directory junction at its exact expected package
   path; never copy or link an entire home/cache tree.

Git for Windows supplies `unzip.exe` here:

`D:\Apps\git\Git\usr\bin\unzip.exe`

The template inspection scripts call `unzip`. If it is not on `PATH`, prepend:

```powershell
$env:Path = 'D:\Apps\git\Git\usr\bin;' + $env:Path
```

`soffice` was not installed, and PowerPoint COM failed in the non-interactive
session. Use artifact-tool rendering.

`D:\tmp` denied creation during this run despite being an expected writable
root. Preferred scratch is the OS temporary directory; when that is blocked,
use a `.codex-work` directory under the user-requested PPT output folder and
keep all intermediates there.

The project-level skill lives at:

`D:\fmagent\FM-Agent\.codex\skills\fm-agent-progress-ppt`

`D:\fmagent\.agents` was read-only in this environment, so skill initialization
there failed.

