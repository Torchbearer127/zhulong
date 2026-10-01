# DeepSeek Harness 接入说明

烛龙可通过共享 skill 目录安装到 DeepSeek Harness（dsh）。这是有限接入，不是 dsh 原生插件，
也不表示完整的 docker 审计闭环已经通过。下文只覆盖一组有记录的配置；本次测试的 `0.1.0-rc.7`
版本在当时处于开发预览阶段，不能据此推及其他版本、模型来源、模型或部署方式。

## 安装

dsh 使用 `$DSH_AGENTS_HOME` 作为 Agent 配置根目录；未设置时默认为 `~/.agents`，并从
`<Agent 配置根目录>/skills/` 发现 skill。在插件根目录运行：

```bash
agents_home="${DSH_AGENTS_HOME:-$HOME/.agents}"
bash scripts/sync_to_codex_skill.sh --codex-skills-dir "$agents_home/skills"
python3 "$agents_home/skills/zhulong/scripts/selftest_plugin.py"
```

同步脚本名称是历史沿用的；它写入共享 skill 布局，不会调用 Codex。传给脚本的是 `skills/` 目录，
不是 `DSH_AGENTS_HOME` 本身。替换已有烛龙副本前，脚本可能会创建备份。同步后重新启动 dsh。

## 调用与来源核对

按本机配置启动 dsh，再通过它的 skill 发现与调用工具选择 `zhulong`。不要把 Codex 的 `$zhulong`
语法当作 dsh 命令。可以这样提出审计请求：

```text
请使用已安装的 zhulong skill 审计这个本地仓库：
/path/to/repo

输出语言：zh-CN。
```

磁盘上存在安装目录，不等于 dsh 实际加载了该副本。请检查 dsh 的 `agentsHome`、`dshHome`、
自定义 skill 目录和项目级来源。如果需要确认同名来源，可使用隔离的 dsh 配置及带唯一标记的无害
skill 副本，再让运行时的 skill 工具读取该标记。不要删除或覆盖其他副本来掩盖冲突。对已安装启动器
运行 `--print-skill-root` 只能显示该启动器自身的包根目录，不能证明 dsh 实际加载了哪份 skill。

## 权限与恢复

skill 提示词不会强制工具权限。已检查的无界面 dsh 配置没有按命令或路径设置白名单；记录中的一次真实会话
还查询了超出授权范围的全局 docker 清单。请只在明确授权的目标和操作范围内执行，并核对重要工具操作及其
结果。权限检查拒绝某项操作时就停止，不要换通道绕过。

docker 不可用或环境不安全时，保留工作区并暂停验证。不要在宿主机运行 PoC。中断后回到同一工作区，
检查权威事件日志、当前状态和 checkpoint，再从记录的阶段继续。聊天摘要或宿主机命令都不能证明 dsh
执行或完成了相应步骤。

## 已测范围

| 项目 | 有记录的配置与限制 |
| --- | --- |
| dsh | `0.1.0-rc.7`；本次文档收口未重新核验对应源码提交或 macOS 具体版本号。 |
| 主机与配置 | macOS；Volcengine Agent Plan 和 `deepseek-v4.1-flash`；无界面运行配置。权限检查读取的配置组合包含 `dsh-base` 与 `dsh-headless`；会话记录中出现 `skill`、`read`、`bash` 调用。没有保存完整组件清单。 |
| docker 预检 | 合成样例验证前观察到 docker 守护进程 `29.4.0`、`linux/aarch64`。这不是通用兼容性矩阵。 |
| 离线回归环境 | Python `3.12.14`、PyYAML `6.0.3`、python-docx `1.2.0`、Pillow `12.3.0`；测试中的 docker 调用由仅拒绝请求的替身拦截。 |

历史记录支持在该配置下发现共享 skill、读取参考文件和解析已安装启动器根目录。另有有限证据覆盖 docker
阻塞、操作被拒或失败、检查点恢复和同名来源选择；这些检查没有覆盖所有配置。

较早的一次真实 dsh 会话在一份旧的无害合成 HTTP 样例上运行独立验证器，并对该样例的标记生成
`confirmed_in_docker` 判定。另一份较新的合成样例由宿主机运行独立验证器；后续处置与交付包契约检查也都由
宿主机执行，并非前述 dsh 会话的续作。交付包构建器因复现命令中的附件引用失败。没有提升正式交付包，也没有
完成工作区最终收尾。这不能证明 dsh 驱动的完整审计通过，也不是上游漏洞发现。当前只能说明共享 skill 接入
已有部分验证；完整端到端支持仍未证实。
