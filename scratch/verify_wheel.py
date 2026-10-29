import zipfile

z = zipfile.ZipFile("dist/bap_ltd-1.9.2-py3-none-any.whl")
content = z.read("bap/bap_install.py").decode("utf-8")
has_registration = 'claude_settings["hooks"]["SessionEnd"]' in content
has_cleanup = 'claude_settings["hooks"].pop("SessionEnd", None)' in content

print(f"SessionEnd registration present: {has_registration}")
print(f"SessionEnd cleanup present     : {has_cleanup}")

assert not has_registration, "Error: SessionEnd registration is still present!"
assert has_cleanup, "Error: SessionEnd cleanup is missing!"
print("Wheel validation passed: bap-ltd 1.9.2 is clean!")
