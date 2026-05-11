"""
CLI 入口

提供敏感的 guard 命令行工具。
"""

import json
import os
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from .config import GuardConfig, load_config
from .detector import SensitiveDetector
from .mapping import MappingStore
from .llm_client import GuardedLLMClient
from .agent_correct import RuleAgent, auto_correct as run_auto_correct

app = typer.Typer(help="敏感信息过滤 CLI 工具")
console = Console()

# 会话历史存储路径
_SESSION_DB_PATH = Path.home() / ".sensitive_guard" / "sessions.json"


def _load_sessions() -> dict[str, list[dict[str, str]]]:
    """从 JSON 文件加载会话历史"""
    try:
        if _SESSION_DB_PATH.exists():
            return json.loads(_SESSION_DB_PATH.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


def _save_sessions(sessions: dict[str, list[dict[str, str]]]):
    """保存会话历史到 JSON 文件"""
    _SESSION_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    _SESSION_DB_PATH.write_text(json.dumps(sessions, ensure_ascii=False, indent=2), encoding="utf-8")


@app.command()
def detect(
    text: Optional[str] = typer.Option(None, "-t", "--text", help="待检测文本"),
    file: Optional[Path] = typer.Option(None, "-f", "--file", help="待检测文件"),
    config_path: Path = typer.Option("config.yaml", "-c", "--config", help="配置文件路径"),
    json_output: bool = typer.Option(False, "--json", help="JSON 格式输出"),
    auto_correct: bool = typer.Option(False, "--auto-correct", help="检测不通过时调 Agent 分析漏检"),
):
    """检测文本中的敏感信息"""
    cfg = load_config(config_path)
    detector = SensitiveDetector(rules=cfg.rules, sensitive_words=cfg.sensitive_words)

    if file:
        text = file.read_text(encoding="utf-8")
    elif not text:
        text = sys.stdin.read()

    result = detector.detect(text)

    if json_output:
        output = {
            "has_sensitive": result.has_sensitive,
            "total_count": result.total_count,
            "matches": [
                {
                    "rule": m.rule_name,
                    "text": m.matched_text,
                    "position": f"{m.start}-{m.end}",
                }
                for m in result.matches
            ],
        }
        console.print(json.dumps(output, indent=2, ensure_ascii=False))
    else:
        if result.has_sensitive:
            console.print(f"[yellow]检测到 {result.total_count} 处敏感信息:[/yellow]")
            table = Table("规则", "内容", "位置")
            for m in result.matches:
                table.add_row(m.rule_name, m.matched_text, f"{m.start}-{m.end}")
            console.print(table)
        else:
            console.print("[green]未检测到敏感信息[/green]")

    # Agent 自修正
    if auto_correct and cfg.agent.api_key:
        updated_rules, suggestions = run_auto_correct(text, cfg, result)
        if suggestions:
            console.print(f"\n[bold cyan]Agent 建议 {len(suggestions)} 条规则修正:[/bold cyan]")
            for s in suggestions:
                action_color = {"add": "green", "modify": "yellow", "disable": "red"}
                color = action_color.get(s.action, "white")
                console.print(f"  [{color}]{s.action}[/{color}] {s.rule_name} (置信度: {s.confidence:.2f})")
                console.print(f"    [dim]{s.reason}[/dim]")
                console.print(f"    pattern: [cyan]{s.pattern}[/cyan]")
            cfg.rules = updated_rules
            # 将更新写回 config.yaml
            _write_rules_to_config(config_path, updated_rules)
            console.print(f"\n[green]规则已更新至 {config_path}[/green]")
        else:
            console.print("\n[dim]Agent 未发现需要修正的规则[/dim]")
    elif auto_correct:
        console.print("[red]无法执行自修正: 未设置 API Key[/red]")


@app.command()
def filter(
    text: Optional[str] = typer.Option(None, "-t", "--text", help="待过滤文本"),
    file: Optional[Path] = typer.Option(None, "-f", "--file", help="待过滤文件"),
    config_path: Path = typer.Option("config.yaml", "-c", "--config", help="配置文件路径"),
    dry_run: bool = typer.Option(False, "--dry-run", help="仅检测不替换"),
):
    """过滤文本中的敏感信息"""
    cfg = load_config(config_path)
    detector = SensitiveDetector(rules=cfg.rules, sensitive_words=cfg.sensitive_words)
    mapping = MappingStore(behavior=cfg.behavior)

    if file:
        text = file.read_text(encoding="utf-8")
    elif not text:
        text = sys.stdin.read()

    result = detector.detect(text)

    if dry_run:
        if result.has_sensitive:
            console.print(f"[yellow]将替换 {result.total_count} 处敏感信息[/yellow]")
            for m in result.matches:
                placeholder = mapping.get_placeholder(m.matched_text)
                console.print(f"  {m.matched_text[:30]} → {placeholder}")
        else:
            console.print("[green]无需替换[/green]")
    else:
        filtered = mapping.replace_all(text, result.matches)
        console.print(filtered)
        if result.has_sensitive:
            console.print(f"\n[dim]替换了 {result.total_count} 处敏感信息[/dim]")


@app.command()
def chat(
    prompt: str = typer.Argument(..., help="用户输入"),
    config_path: Path = typer.Option("config.yaml", "-c", "--config", help="配置文件路径"),
    model: Optional[str] = typer.Option(None, "-m", "--model", help="模型名称"),
    system: Optional[str] = typer.Option(None, "-s", "--system", help="系统提示词"),
    session: Optional[str] = typer.Option(None, "--session", help="会话 ID，同一 ID 保留对话历史"),
    reset: bool = typer.Option(False, "--reset", help="重置指定会话的历史"),
    auto_correct: bool = typer.Option(False, "--auto-correct", help="对话结束后自动分析漏检并修正规则"),
    show_detection: bool = typer.Option(False, "--show-detection", help="显示检测详情"),
    show_raw: bool = typer.Option(False, "--show-raw", help="显示原始响应（占位符未还原）"),
):
    """发送聊天消息，自动过滤敏感信息。使用 --session 保持多轮对话上下文。"""
    cfg = load_config(config_path)

    if not cfg.agent.api_key:
        console.print("[red]错误: 未设置 API Key，请在 config.yaml 中配置 agent.api_key 或设置环境变量[/red]")
        raise typer.Exit(1)

    # 处理会话历史
    if session:
        sessions = _load_sessions()
        if reset:
            sessions.pop(session, None)
            _save_sessions(sessions)
            console.print(f"[dim]会话 {session} 已重置[/dim]")
        history = sessions.get(session, [])
    else:
        history = []

    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    # 注意：history 不包含 system prompt，只有纯对话
    # 如果用户传了 system，把它放在 history 之前
    valid_history = [m for m in history if m.get("role") != "system"]
    messages.extend(valid_history)
    messages.append({"role": "user", "content": prompt})

    with console.status("[bold green]请求中...[/bold green]"):
        with GuardedLLMClient(guard_config=cfg) as client:
            response = client.chat(messages, model=model)

    # 保存会话历史
    if session:
        sessions = _load_sessions()
        cfg_detector = SensitiveDetector(rules=cfg.rules, sensitive_words=cfg.sensitive_words)
        cfg_mapping = MappingStore(behavior=cfg.behavior)
        # 持久化存储占位符版本（防止文件泄露）
        sanitized_prompt = cfg_mapping.replace_all(prompt, cfg_detector.detect(prompt).matches)
        assistant_msg = {"role": "assistant", "content": response.raw_content}
        sessions[session] = history + [
            {"role": "user", "content": sanitized_prompt},
            assistant_msg,
        ]
        _save_sessions(sessions)
        console.print(f"[dim]会话 {session}: {len(sessions[session])} 条消息[/dim]")

    if show_detection:
        det = response.detection
        if det.has_sensitive:
            console.print(f"\n[yellow]检测到 {det.total_count} 处敏感信息:[/yellow]")
            table = Table("规则", "内容", "→", "占位符")
            for m in det.matches:
                ph = client.mapping.get_placeholder(m.matched_text)
                table.add_row(m.rule_name, m.matched_text[:40], "→", ph)
            console.print(table)

    if show_raw:
        console.rule("原始响应（占位符）")
        console.print(response.raw_content)

    console.rule("回复")
    console.print(response.content)

    console.print(f"\n[dim]映射总数: {response.mapping_stats['total_mappings']}[/dim]")

    # Agent 自修正
    if auto_correct and cfg.agent.api_key:
        detector = SensitiveDetector(rules=cfg.rules, sensitive_words=cfg.sensitive_words)
        detect_result = detector.detect(prompt)
        updated_rules, suggestions = run_auto_correct(prompt, cfg, detect_result)
        if suggestions:
            console.print(f"\n[bold cyan]Agent 建议 {len(suggestions)} 条规则修正:[/bold cyan]")
            for s in suggestions:
                action_color = {"add": "green", "modify": "yellow", "disable": "red"}
                color = action_color.get(s.action, "white")
                console.print(f"  [{color}]{s.action}[/{color}] {s.rule_name} (置信度: {s.confidence:.2f})")
                console.print(f"    [dim]{s.reason}[/dim]")
                console.print(f"    pattern: [cyan]{s.pattern}[/cyan]")
            _write_rules_to_config(config_path, updated_rules)
            console.print(f"[green]规则已更新至 {config_path}[/green]")
        else:
            console.print("\n[dim]Agent 未发现需要修正的规则[/dim]")
    elif auto_correct:
        console.print("[red]无法执行自修正: 未设置 API Key[/red]")


@app.command()
def mappings(
    config_path: Path = typer.Option("config.yaml", "-c", "--config", help="配置文件路径"),
):
    """查看当前映射统计"""
    cfg = load_config(config_path)
    mapping = MappingStore(behavior=cfg.behavior)
    stats = mapping.stats()

    console.print(f"[bold]映射统计[/bold]")
    console.print(f"  总映射数: {stats['total_mappings']}")
    console.print(f"  数据库: {stats['db_path']}")


def _write_rules_to_config(config_path: Path, rules):
    """将更新后的规则增量合并到 config.yaml"""
    import yaml
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))

    # 以 rules 列表为准更新 raw["rules"]
    existing_rules = raw.get("rules", [])
    rules_index = {r["name"]: i for i, r in enumerate(existing_rules)}

    for new_rule in rules:
        entry = {
            "name": new_rule.name,
            "description": new_rule.description,
            "pattern": new_rule.pattern,
            "enabled": new_rule.enabled,
        }
        if new_rule.name in rules_index:
            existing_rules[rules_index[new_rule.name]] = entry
        else:
            existing_rules.append(entry)

    raw["rules"] = existing_rules
    config_path.write_text(yaml.dump(raw, allow_unicode=True, default_flow_style=False), encoding="utf-8")


@app.command()
def correct(
    text: str = typer.Argument(..., help="待分析文本"),
    config_path: Path = typer.Option("config.yaml", "-c", "--config", help="配置文件路径"),
    sensitivity: float = typer.Option(0.7, "--sensitivity", help="置信度阈值 (0-1)"),
):
    """调用 Agent 分析文本，生成新的检测规则建议"""
    cfg = load_config(config_path)
    if not cfg.agent.api_key:
        console.print("[red]错误: 未设置 API Key[/red]")
        raise typer.Exit(1)

    detector = SensitiveDetector(rules=cfg.rules, sensitive_words=cfg.sensitive_words)
    detect_result = detector.detect(text)
    console.print(f"当前检测命中: {detect_result.total_count} 处")

    with console.status("[bold green]Agent 分析中...[/bold green]"):
        suggestions = run_auto_correct(text, cfg, detect_result)[1]

    if not suggestions:
        console.print("[dim]Agent 未发现需要修正的规则[/dim]")
        return

    console.print(f"\n[bold cyan]Agent 建议 {len(suggestions)} 条规则:[/bold cyan]")
    for s in suggestions:
        action_color = {"add": "green", "modify": "yellow", "disable": "red"}
        color = action_color.get(s.action, "white")
        console.print(f"  [{color}]{s.action}[/{color}] {s.rule_name} (置信度: {s.confidence:.2f})")
        console.print(f"    描述: {s.description}")
        console.print(f"    原因: [dim]{s.reason}[/dim]")
        console.print(f"    regex: [cyan]{s.pattern}[/cyan]")


def main():
    """程序入口"""
    app()


if __name__ == "__main__":
    main()
