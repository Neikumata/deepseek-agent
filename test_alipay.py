import yaml
with open("config.yaml", encoding="utf-8") as f:
    d = yaml.safe_load(f)
alipay = [r for r in d['rules'] if 'alipay' in r['name']]
print(alipay)
# 检查原始文件内容
with open("config.yaml", encoding="utf-8") as f:
    content = f.read()
idx = content.find("alipay_account")
print(content[idx:idx+120])
