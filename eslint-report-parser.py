import json

with open("juice-shop\eslint-report.json", "r", encoding="utf-8") as file:
    data = json.load(file)

if isinstance(data, list):
    reports = data
else:
    reports = [data]

for report in reports:
    file_path = report.get("filePath", "Unknown File")
    errors = report.get("messages", [])
    error_count = report.get("errorCount", 0)
    warning_count = report.get("warningCount", 0)

    if error_count != 0 or warning_count != 0:
        print("=" * 80)
        print(f"File: {file_path}")
        print(f"Errors: {error_count} | Warnings: {warning_count}")

        for idx, error in enumerate(errors, 1):
            print(f"{idx}. Rule: {error.get('ruleId', 'Unknown Rule')}")
            severity = "Error" if error["severity"] == 2 else "sWarning"
            print(f"{severity}")
            print(f"Message: {error['message']}")
            print(f"Location: Line {error['line']}, Column {error['column']}")
            print("-" * 80)

print("\nESLint Analysis Complete!")
