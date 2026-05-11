import sys
sys.path.insert(0, r"C:\Users\user\Documents\deepseek-agents\src")

from sensitive_guard.config import load_config
from sensitive_guard.detector import SensitiveDetector
from sensitive_guard.mapping import MappingStore

# 测试配置加载
cfg = load_config(r"C:\Users\user\Documents\deepseek-agents\config.yaml")
print(f"Rules: {len(cfg.rules)}")
print(f"Strategy: {cfg.behavior.replacement_strategy}")
print(f"Model: {cfg.agent.model}")

# 测试检测器 — 用半角字符确保规则精确命中
detector = SensitiveDetector(rules=cfg.rules, sensitive_words=cfg.sensitive_words)
test_text = "Phone: 13812345678, password=abc123456, api_key: sk-1234567890abcdef, email: test@example.com"
result = detector.detect(test_text)
print(f"\nDetection: {result.total_count} matches")
for m in result.matches:
    print(f"  [{m.rule_name}] \"{m.matched_text}\" @ {m.start}-{m.end}")

# 测试映射替换
mapping = MappingStore(behavior=cfg.behavior)
filtered = mapping.replace_all(test_text, result.matches)
print(f"\nFiltered: {filtered}")

# 测试还原
restored = mapping.restore(filtered)
print(f"Restored: {restored}")
assert restored == test_text, f"Restore failed! {restored} != {test_text}"
print("Restore match: True")

print("\n=== ALL TESTS PASSED ===")
