# Contributing to pcdn-detector-c

Thanks for taking the time to contribute! This document explains how to report
issues, propose changes, and get your work merged. It applies to everyone —
please read it before opening a pull request (PR).

[简体中文](#为本项目做出贡献)

---

## Contributor License Agreement (required)

Before your contribution can be accepted, you must agree to the project's
[Contributor License Agreement](CLA.md).

**By opening a pull request, you confirm that you have read the CLA and agree
to its terms for your present and future contributions.** You do not need to
sign any separate document. A PR that does not satisfy the CLA requirement will
not be merged.

In short, the CLA lets the maintainers and administrators of the project — now
and in the future — relicense your contributions under any
[OSI-approved license](https://opensource.org/licenses). Relicensing your
contribution under a non-OSI (for example proprietary) license requires your
separate explicit authorization.

## Developer Certificate of Origin (required)

Every commit in your pull request must be signed off to certify the
[Developer Certificate of Origin](https://developercertificate.org/) (DCO).
Add a `Signed-off-by` line with your name (the name or handle you go by) and an
email address as the last line of the commit message:

```
fix(firewall): 修正 nftables inet family 的集合命令

Signed-off-by: Jane Doe <jane@example.com>
```

`git commit -s` adds the line automatically, using the name and email from your
Git configuration (set them with `git config user.name` and
`git config user.email`). To add the line to commits that are missing it, run
`git rebase --signoff main`.

The sign-off only needs to identify you — a name or handle together with an
email address is enough; it does not have to be your legal name. By signing
off, you certify that you wrote the contribution or otherwise have the right to
submit it under the project's license. The DCO is a per-commit confirmation and
is required **in addition to** the CLA above; a PR whose commits are not signed
off will not be merged.

## Reporting issues

- Search the existing issues first to avoid duplicates.
- For a bug, include: the version (`pcdn-detect -v`), the OpenWrt / distribution
  version and CPU architecture (`cat /proc/cpuinfo`, `opkg print-architecture`
  or `apk --print-arch`), the compiler and libc you built with (glibc or musl,
  static or dynamic), the interface you capture on, the firewall backend in use
  (`hook` / `iptables` / `nftables`), and clear steps to reproduce.
- Attach the relevant log lines, preferably with `[log] level = "info"` (or
  `"debug"`) enabled. **Redact MAC addresses and public IP addresses** before
  pasting logs, or use `-H` / `--hide-address`.
- For a feature request, describe the use case and the behaviour you expect.
  Keep in mind that this project tracks the behaviour of the upstream Go
  implementation (see [UPSTREAM](UPSTREAM)): if a change also affects the Go
  version, describe how the two should stay aligned.
- Do not report security issues in a public issue — contact the maintainer
  privately instead.

## Development setup

The build instructions live in the [README](README.md#编译) and in
[docs/build.md](docs/build.md). The short version:

```bash
git clone https://github.com/Womsxd/pcdn-detector-c.git
cd pcdn-detector-c
git submodule update --init --recursive   # 或 make deps
make                                     # -> bin/pcdn-detect
make test                                # 单元 / HTTP / CLI 测试
```

Requirements: a C23-capable compiler (GCC 13+ / Clang 16+). No libpcap or
system development packages are involved — capture is implemented directly on
`AF_PACKET` + `TPACKET_V2` with a classic BPF filter, and dependencies
(tomlc99 / cJSON / uthash / picohttpparser) are vendored as **git submodules**
under `third_party/`.

`make STATIC=1` produces a fully static Musl binary, and `make all` produces
static binaries for all architectures under `bin/`. For a fully automatic run —
toolchain provisioning included, or using zig instead of GCC — use the scripts
under `script/` (`./script/gcc-static.sh`, `./script/zig-static.sh`).

Running the binary for real requires `root` or `CAP_NET_RAW` and a LAN-side
interface such as `br-lan`. Unit tests do **not** need privileges, a real
network interface, or a running firewall.

## Making changes

1. Fork the repository and create a branch off `main`, for example
   `fix/nftables-timeout` or `feat/upnp-whitelist`.
2. Keep the change focused. One logical change per PR is much easier to review.
3. Match the existing style: C23 compiled with `-Wall -Wextra`, Chinese
   comments (as in the rest of `src/`), comments only where the logic is not
   self-evident, and no unrelated reformatting. Keep the `src/<模块>.c|h` split —
   `config`, `capture`, `detector`, `filter`, `firewall`, `blocker`, `httpapi`,
   `http`, `state`, `util` — instead of adding cross-cutting code to `app.c`.
   Internal helpers stay `static`; everything shared goes through the matching
   header.
4. Do not patch vendored code under `third_party/` in place. Fixes belong
   upstream, or must be wrapped/worked around in `src/` so the submodule can
   still be updated.
5. Add or update tests in `tests/` (`test_core.c`, `test_http.c`) for
   behaviour you change, and keep `make test` green.
6. Update the documentation when your change affects user-visible behaviour:
   `README.md` for options and defaults, and the matching page under `docs/`
   (`build.md`, `memory.md`, `filter.md`, `firewall.md`, `upnp.md`, `http.md`).
   The default config template generated by `--init-config` must stay in sync
   with any new or changed config key, and must remain loadable by the Go
   version. Documentation must describe what the code actually does — do not
   claim capabilities or protections that are not implemented.

## Before you open a pull request

Run the same checks locally, and make sure they pass:

```bash
make clean && make       # 无新增告警
make test                # 单元 / HTTP / CLI 测试
make STATIC=1            # 若改动了抓包、防火墙或 HTTP 层
```

If the build produces warnings, or any test fails, fix it before requesting
review.

## Pull request process

- Open the PR against the `main` branch.
- Use a clear title and describe **what** changed and **why**. Link the issue
  it fixes (`Fixes #123`) where applicable.
- Use Conventional Commit style for the PR title/commits (`feat:`, `fix:`,
  `docs:`, `refactor:`, `test:`, `ci:`, `chore:`), optionally with a scope,
  e.g. `fix(firewall): …`, `refactor(detector): …`.
- Confirm in the PR description that you agree to the CLA.
- Sign off every commit with a `Signed-off-by` line (see above).
- Keep the branch up to date with `main`; resolve conflicts yourself.
- Respond to review feedback. Reviewers may request changes, and a maintainer
  makes the final decision on whether a PR is merged.

---

# 为本项目做出贡献

感谢您愿意花时间做出贡献！本文档说明如何报告问题、提交改动，以及如何让您的改动被合并。
它适用于所有人——在发起 Pull Request（PR）之前，请先阅读本文档。

[English](#contributing-to-pcdn-detector-c)

---

## 贡献者许可协议（必需）

在接受您的贡献之前，您必须同意本项目的[贡献者许可协议](CLA.md)。

**发起 Pull Request 即表示您确认已阅读 CLA，并同意其条款适用于您当前及未来的贡献。**
无需另行签署任何单独文件。不满足 CLA 要求的 PR 将不会被合并。

简言之，CLA 允许本项目的维护者与管理者（当前及未来）将您的贡献内容按任意
[OSI 批准许可证](https://opensource.org/licenses)进行再许可；若要以非 OSI（例如专有）
许可证再许可您的贡献，须另行取得您的明确授权。

## 开发者原创声明（DCO，必需）

Pull Request 中的每一个提交都必须签署，以证明遵守
[开发者原创声明](https://developercertificate.org/)（Developer Certificate of
Origin，DCO）。请在提交信息（commit message）的最后一行加上 `Signed-off-by`，内容为
您的称呼（您使用的名字或网名）与邮箱：

```
fix(firewall): 修正 nftables inet family 的集合命令

Signed-off-by: 张三 <zhangsan@example.com>
```

`git commit -s` 会自动添加该行，姓名与邮箱取自 Git 配置（请先用 `git config user.name`
与 `git config user.email` 设置）。若已有提交缺少该行，可运行
`git rebase --signoff main` 补上。

签署行只需能标识您本人——一个称呼或网名加上邮箱即可，无需使用法定姓名。签署即表示
您证明该贡献由您本人创作，或您有权按本项目许可证提交它。DCO 是对每个提交的确认，与
上述 CLA **同时**适用；未签署的 PR 将不会被合并。

## 报告问题

- 请先搜索已有 issue，避免重复。
- 报告 bug 时请提供：版本号（`pcdn-detect -v`）、OpenWrt / 发行版版本与 CPU 架构
  （`cat /proc/cpuinfo`、`opkg print-architecture` 或 `apk --print-arch`）、构建所用的
  编译器与 libc（glibc / musl，静态或动态）、抓包使用的网卡、所用防火墙后端
  （`hook` / `iptables` / `nftables`），以及清晰的可复现步骤。
- 请附相关日志，最好开启 `[log] level = "info"`（或 `"debug"`）。粘贴前请**隐去 MAC
  与公网 IP**，或使用 `-H` / `--hide-address` 运行。
- 功能建议请描述使用场景与期望行为。本项目的行为对齐上游 Go 实现（见 [UPSTREAM](UPSTREAM)）：
  若该改动同时影响 Go 版本，请说明两者应如何保持一致。
- 安全相关问题请勿在公开 issue 中报告，请私下联系维护者。

## 开发环境

构建步骤见 [README](README.md#编译) 与 [docs/build.md](docs/build.md)。简要流程：

```bash
git clone https://github.com/Womsxd/pcdn-detector-c.git
cd pcdn-detector-c
git submodule update --init --recursive   # 或 make deps
make                                     # 产出 bin/pcdn-detect
make test                                # 单元 / HTTP / CLI 测试
```

环境要求：支持 C23 的编译器（GCC 13+ / Clang 16+）。本项目不依赖 libpcap 或系统开发包
——抓包直接基于 `AF_PACKET` + `TPACKET_V2` 与内核经典 BPF 实现；依赖（tomlc99 / cJSON /
uthash / picohttpparser）以 **git submodule** 形式放在 `third_party/`。

`make STATIC=1` 产出 Musl 全静态二进制；`make all` 会在 `bin/` 下产出各架构的静态产物。
要连工具链一起自动准备、或改用 zig 编译，用 `script/` 下的脚本
（`./script/gcc-static.sh`、`./script/zig-static.sh`）。

实际运行二进制需要 `root` 或 `CAP_NET_RAW`，并指定 LAN 侧网卡（如 `br-lan`）。单元测试
**不需要**特权、真实网卡或运行中的防火墙。

## 提交改动

1. Fork 仓库并从 `main` 创建分支，例如 `fix/nftables-timeout` 或
   `feat/upnp-whitelist`。
2. 保持改动聚焦。一个 PR 只做一件事，更易于评审。
3. 遵循既有风格：C23 代码在 `-Wall -Wextra` 下不得产生新增告警；注释使用中文（与 `src/`
   下现有代码一致）；仅在逻辑不自明处添加注释；不要顺手重排无关代码。请保持
   `src/<模块>.c|h` 的职责划分（`config`、`capture`、`detector`、`filter`、`firewall`、
   `blocker`、`httpapi`、`http`、`state`、`util`），不要把横跨各模块的代码堆到 `app.c`。
   内部辅助函数保持 `static`，需要跨文件使用的一律通过对应头文件声明。
4. 不要直接修改 `third_party/` 下的第三方代码。修复应提交到上游，或在 `src/` 中封装 /
   规避，以保证 submodule 仍可升级。
5. 对您改动的行为在 `tests/`（`test_core.c`、`test_http.c`）中补充或更新测试，并保持
   `make test` 通过。
6. 当改动影响用户可见行为时，请同步更新文档：选项与默认值改 `README.md`，对应细节改
   `docs/` 下的相应页面（`build.md`、`memory.md`、`filter.md`、`firewall.md`、`upnp.md`、
   `http.md`）。`--init-config` 生成的默认配置模板必须与新增或修改的配置项同步，且仍需
   能被 Go 版本正常加载。文档必须如实描述代码的实际行为，不得宣称尚未实现的能力或保护措施。

## 发起 Pull Request 之前

请在本地运行以下检查并确保全部通过：

```bash
make clean && make       # 无新增告警
make test                # 单元 / HTTP / CLI 测试
make STATIC=1            # 若改动了抓包、防火墙或 HTTP 层
```

若构建出现告警，或任一测试失败，请先修复再请求评审。

## Pull Request 流程

- 向 `main` 分支发起 PR。
- 使用清晰的标题，并说明**改了什么**以及**为什么**。若相关，请关联对应 issue
  （`Fixes #123`）。
- PR 标题/提交信息请使用 Conventional Commits 风格（`feat:`、`fix:`、`docs:`、
  `refactor:`、`test:`、`ci:`、`chore:`），可附带作用域，例如 `fix(firewall): …`、
  `refactor(detector): …`。
- 在 PR 描述中确认您同意 CLA。
- 为每个提交添加 `Signed-off-by` 签署行（见上）。
- 保持分支与 `main` 同步，并自行解决冲突。
- 回应评审意见。评审者可能要求修改，最终是否合并由维护者决定。
