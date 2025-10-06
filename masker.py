#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
py_embute.py — Embute e desembute arquivos em scripts Python autoextraíveis.

Uso:
  Embutir:   python py_embute.py embutir <arquivo> -o <saida.py>
  Desembutir:python py_embute.py desembutir <script.py> [-o <arquivo_saida>]

O script gerado (saida.py) também é autoextraível:
  python saida.py                # extrai com o nome original
  python saida.py --saida X.zip  # extrai para o caminho escolhido
  python saida.py --stdout       # escreve bytes no stdout
  python saida.py --info         # mostra metadados
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import textwrap
from datetime import datetime

MAGIC = "#==[EMBUTE_V1]==#"

TEMPLATE = '''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
{magic}
# Script autoextraível gerado por py_embute.py
# Dica: `python {self_name} --info` para ver metadados
EMBUTE_META_JSON = r\"\"\"{meta_json}\"\"\"
EMBUTE_DATA_B64 = (
{data_chunks}
)

def _sha256_bytes(b: bytes) -> str:
    import hashlib
    h = hashlib.sha256()
    h.update(b)
    return h.hexdigest()

def _info(meta):
    print("Arquivo original : ", meta.get("orig_name"))
    print("Tamanho (bytes)  : ", meta.get("size"))
    print("SHA256           : ", meta.get("sha256"))
    print("Gerado em        : ", meta.get("created_at"))
    print("Descricao        : ", meta.get("description"))

def _extract(meta, out_path=None, to_stdout=False):
    import base64, sys, os, json
    data_b64 = EMBUTE_DATA_B64
    raw = base64.b64decode(data_b64.encode('ascii'))
    # Verifica integridade
    if meta.get("sha256") != _sha256_bytes(raw):
        print("ERRO: checksum não confere! Abortando.", file=sys.stderr)
        sys.exit(2)
    if to_stdout:
        # grava bytes no stdout sem conversão de texto
        sys.stdout.buffer.write(raw)
        return
    dest = out_path or meta.get("orig_name") or "saida.bin"
    os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
    with open(dest, "wb") as f:
        f.write(raw)
    print("Extraído para:", dest)

def main():
    import argparse, json, sys
    parser = argparse.ArgumentParser(
        description="Script autoextraível (gerado por py_embute.py)"
    )
    parser.add_argument("--info", action="store_true", help="Mostra metadados e sai")
    parser.add_argument("--extrair", action="store_true", help="Extrai o arquivo embutido")
    parser.add_argument("--saida", help="Caminho de saída ao extrair")
    parser.add_argument("--stdout", action="store_true", help="Escreve bytes no stdout")
    args = parser.parse_args()
    meta = json.loads(EMBUTE_META_JSON)

    if args.info and (args.extrair or args.stdout or args.saida):
        print("--info não combina com opções de extração.", file=sys.stderr)
        sys.exit(1)

    if args.info:
        _info(meta)
        return

    # Padrão: extrair se chamado sem --info
    _extract(meta, out_path=args.saida, to_stdout=args.stdout)

if __name__ == "__main__":
    main()
'''

def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()

def _read_bytes(path: str) -> bytes:
    with open(path, 'rb') as f:
        return f.read()

def _write_text(path: str, txt: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, 'w', encoding='utf-8', newline='\n') as f:
        f.write(txt)
    os.chmod(path, 0o755)

def embutir(input_path: str, output_path: str, description: str | None = None) -> None:
    if not os.path.isfile(input_path):
        raise FileNotFoundError(f"Arquivo não encontrado: {input_path}")
    data = _read_bytes(input_path)
    b64 = base64.b64encode(data).decode('ascii')

    # Quebra o base64 em linhas legíveis (para reduzir diffs e evitar linhas gigantes)
    chunked = textwrap.wrap(b64, width=120)
    data_chunks_py = "\n".join(f"    \"{line}\"" for line in chunked)

    meta = {
        "orig_name": os.path.basename(input_path),
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "created_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "description": description or f"Arquivo embutido a partir de {input_path}",
        "format_version": 1,
    }
    meta_json = json.dumps(meta, ensure_ascii=False)

    script_text = TEMPLATE.format(
        magic=MAGIC,
        self_name=os.path.basename(output_path) if output_path else "saida.py",
        meta_json=meta_json,
        data_chunks=data_chunks_py,
    )
    _write_text(output_path, script_text)
    print(f"Gerado script autoextraível: {output_path}")
    print(f"Arquivo original: {meta['orig_name']} ({meta['size']} bytes)")
    print(f"SHA256: {meta['sha256']}")

def _is_embedded_script(path: str) -> bool:
    try:
        with open(path, 'r', encoding='utf-8') as f:
            head = f.read(4096)
        return MAGIC in head
    except Exception:
        return False

def desembutir(script_path: str, output_path: str | None = None, to_stdout: bool = False) -> None:
    if not _is_embedded_script(script_path):
        raise ValueError("O arquivo informado não parece ser um script gerado pelo py_embute.py.")
    # Executa o script alvo como módulo Python com --info para obter os metadados
    # e com --stdout para receber os bytes diretamente.
    if to_stdout:
        # Encaminha bytes direto ao stdout do chamador
        import runpy, types, io
        # Carrega o script como módulo isolado e intercepta sys.argv
        argv_backup = sys.argv[:]
        stdout_backup = sys.stdout
        try:
            sys.argv = [script_path, "--stdout"]
            sys.stdout = sys.__stdout__  # manter stdout real em binário
            runpy.run_path(script_path, run_name="__main__")
        finally:
            sys.argv = argv_backup
            sys.stdout = stdout_backup
        return

    # Primeiro, pergunta o nome original
    import subprocess, json, tempfile
    with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
        tmp_path = tmp.name
    try:
        info = _collect_info(script_path)
        dest = output_path or info.get("orig_name") or "saida.bin"
        # Agora extrai para 'dest'
        _invoke_extract(script_path, dest)
        print(f"Extraído para: {dest}")
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass

def _collect_info(script_path: str) -> dict:
    # Executa `python script.py --info` e interpreta a saída básica
    import subprocess, json, re
    # Para robustez, vamos abrir o script e ler o JSON diretamente
    with open(script_path, 'r', encoding='utf-8') as f:
        txt = f.read()
    # Captura EMBUTE_META_JSON r"""..."""
    start = txt.find('EMBUTE_META_JSON = r"""')
    if start == -1:
        return {}
    start += len('EMBUTE_META_JSON = r"""')
    end = txt.find('"""', start)
    meta_json = txt[start:end]
    try:
        return json.loads(meta_json)
    except Exception:
        return {}

def _invoke_extract(script_path: str, out_path: str) -> None:
    # Chama: python script.py --extrair --saida <out_path>
    import subprocess, sys
    cmd = [sys.executable, script_path, "--extrair", "--saida", out_path]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr or "")
        raise RuntimeError("Falha ao extrair do script.")
    # Repassa mensagens amigáveis
    if proc.stdout.strip():
        print(proc.stdout.strip())

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Embute e desembute arquivos em scripts Python autoextraíveis."
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    p_emb = sub.add_parser("embed", help="Embutir um arquivo em um script .py")
    p_emb.add_argument("arquivo", help="Caminho do arquivo de entrada")
    p_emb.add_argument("-o", "--saida", required=True, help="Script .py de saída")
    p_emb.add_argument("-d", "--descricao", default=None, help="Descrição opcional")

    p_des = sub.add_parser("unembed", help="Extrair de um script .py gerado")
    p_des.add_argument("script", help="Script .py que contém o arquivo embutido")
    p_des.add_argument("-o", "--saida", help="Arquivo de saída (padrão: nome original)")
    p_des.add_argument("--stdout", action="store_true", help="Escreve bytes no stdout")

    return p

def main():
    parser = _build_parser()
    args = parser.parse_args()

    if args.cmd == "embed":
        embutir(args.arquivo, args.saida, description=args.descricao)
    elif args.cmd == "unembed":
        desembutir(args.script, args.saida, to_stdout=args.stdout)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

