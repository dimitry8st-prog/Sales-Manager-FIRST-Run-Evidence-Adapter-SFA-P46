"""Проверка исходного комплекта и разрешённых новых файлов."""
import pathlib,json,hashlib
ROOT=pathlib.Path(__file__).resolve().parent
manifest=json.loads((ROOT/'PROTECTED_SHA256.json').read_text(encoding='utf-8'))
bad=[]
for rel,digest in manifest.items():
 f=ROOT/rel
 if f.is_symlink() or not f.is_file() or hashlib.sha256(f.read_bytes()).hexdigest()!=digest:
  bad.append('PROTECTED:'+rel)
for f in ROOT.rglob('*'):
 rel=f.relative_to(ROOT).as_posix()
 if f.is_symlink(): bad.append('LINK:'+rel);continue
 if not f.is_file():continue
 if '__pycache__' in f.parts or f.suffix=='.pyc':continue
 if rel in manifest or rel=='PROTECTED_SHA256.json' or rel=='source/audit_release/command_evidence.py' or rel.startswith('candidate_tests/') or rel.startswith('return/'):continue
 bad.append('UNAUTHORIZED:'+rel)
print(json.dumps({'protected_files':len(manifest),'mismatch':sorted(set(bad))},ensure_ascii=True))
raise SystemExit(1 if bad else 0)
