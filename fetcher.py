import json
import os
import tempfile
import requests
from urllib.parse import quote
from javascript import eval_js


def key_fetcher(script_url: str):
    harness = f"""
const result = await (async () => {{
  const captured = {{ key: null }};
  const bytesToBase64 = (value) => {{
    const view = value instanceof ArrayBuffer
      ? new Uint8Array(value)
      : new Uint8Array(value.buffer || value);
    return Buffer.from(view).toString("base64");
  }};

  Object.defineProperty(globalThis, "window", {{ value: globalThis, configurable: true }});
  Object.defineProperty(globalThis, "self", {{ value: globalThis, configurable: true }});
  Object.defineProperty(globalThis, "navigator", {{
    value: {{ userAgent: "", languages: [], plugins: [], mimeTypes: [] }},
    configurable: true
  }});
  Object.defineProperty(globalThis, "document", {{
    value: {{
      createElement: () => ({{ style: {{}}, getContext: () => null }}),
      querySelectorAll: () => [],
      documentElement: {{ getAttributeNames: () => [] }},
      hasFocus: () => true
    }},
    configurable: true
  }});
  Object.defineProperty(globalThis, "location", {{
    value: {{ href: "http://localhost/" }},
    configurable: true
  }});

  globalThis.atob ||= ((s) => Buffer.from(s, "base64").toString("binary"));
  globalThis.btoa ||= ((s) => Buffer.from(s, "binary").toString("base64"));

  const subtle = globalThis.crypto.subtle;
  const originalImportKey = subtle.importKey.bind(subtle);
  subtle.importKey = (format, keyData, algorithm, extractable, keyUsages) => {{
    if (String(format).toLowerCase() === "spki") {{
      captured.key = bytesToBase64(keyData);
      return Promise.reject(new Error("__CAPTURED_KEY__"));
    }}
    return originalImportKey(format, keyData, algorithm, extractable, keyUsages);
  }};

  try {{
    const moduleUrl = {json.dumps(script_url)};
    const response = await fetch(moduleUrl);
    if (!response.ok) {{
      throw new Error(`failed to fetch module: ${{response.status}}`);
    }}
    const source = await response.text();
    const sourceUrl = `\\n//# sourceURL=${{moduleUrl}}`;
    const dataUrl = "data:text/javascript;charset=utf-8;base64,"
      + Buffer.from(source + sourceUrl).toString("base64");
    const mod = await import(dataUrl);
    const candidates = [];
    if (typeof mod["encryptData"] === "function") {{
      candidates.push(mod["encryptData"]);
    }}
    for (const value of Object.values(mod)) {{
      if (typeof value === "function" && !candidates.includes(value)) {{
        candidates.push(value);
      }}
    }}

    for (const candidate of candidates) {{
      try {{
        await candidate("x");
      }} catch (error) {{
        if (captured.key) break;
      }}
      if (captured.key) break;
    }}
  }} finally {{
    subtle.importKey = originalImportKey;
  }}

  if (!captured.key) {{
    throw new Error("SPKI importKey call was not captured");
  }}
  if (!captured.key.startsWith("MIIBIjANB")) {{
    throw new Error(`captured key does not start with "MIIBIjANB"`);
  }}
  return captured.key;
}})();

export default result;
"""

    tmp = tempfile.NamedTemporaryFile("w", suffix=".mjs", delete=False, encoding="utf-8")
    try:
        tmp.write(harness)
        tmp.close()
        return eval_js(f"import({json.dumps("file://" + quote(os.path.abspath(tmp.name)))}).then((m) => m.default)")
    finally:
        try:
            os.unlink(tmp.name)
        except FileNotFoundError:
            pass


def fetcher():
    s = requests.get("https://js.prosopo.io/js/procaptcha.bundle.js").text.splitlines(keepends=True)
    h = s[0].split('from "')[1].split('"')[0].split("./")[1]
    print(f"bundle.js --> {h}")
    t = requests.get(f"https://js.prosopo.io/js/{h}").text
    e = t.split('(await import("./')[1].split('"')[0]
    if not e.startswith("captchaRenderer-") and not e.endswith(".js"):
        return None
    print(f"{h} --> {e}")
    g = requests.get(f"https://js.prosopo.io/js/{e}").text
    b = g.split('(await import("./')[3].split('"')[0]
    print(f"{e} --> {b}")
    key = key_fetcher(f"https://js.prosopo.io/js/{b}")
    print(key)
    return key



if __name__ == "__main__":
    print(fetcher())
