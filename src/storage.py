"""原始材料文件存储：内容寻址、只追加、不可改名覆盖。

- 入库时先流式计算 SHA-256，再按摘要落盘；同摘要文件只存一份但不影响新登记记录。
- 文件名不含案件/人员语义，防止路径泄露；元数据全部在数据库。
- 不提供更新/删除接口；作废只改数据库状态，原件仍可用于审计核验。
"""

import hashlib
import os
import pathlib


class BlobStore:
    def __init__(self, root: pathlib.Path):
        self.root = pathlib.Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path_for(self, digest: str) -> pathlib.Path:
        # 两级分桶，避免单目录文件过多
        return self.root / digest[:2] / digest[2:4] / digest

    def put_stream(self, stream, chunk_size: int = 1024 * 1024) -> tuple[str, int, bool]:
        """返回 (sha256, 字节数, 是否已有相同原件)。不接受文件路径，强制流式。"""
        hasher = hashlib.sha256()
        size = 0
        staging = self.root / (".staging-" + hashlib.sha256(os.urandom(16)).hexdigest())
        with open(staging, "wb") as out:
            while True:
                chunk = stream.read(chunk_size)
                if not chunk:
                    break
                hasher.update(chunk)
                size += len(chunk)
                out.write(chunk)
        digest = hasher.hexdigest()
        target = self._path_for(digest)
        existed = target.exists()
        if not existed:
            target.parent.mkdir(parents=True, exist_ok=True)
            os.replace(staging, target)
            os.chmod(target, 0o440)
        else:
            staging.unlink()
        return digest, size, existed

    def open_read(self, digest: str):
        path = self._path_for(digest)
        if not path.exists():
            raise FileNotFoundError(f"原件缺失: {digest}")
        return open(path, "rb")

    def exists(self, digest: str) -> bool:
        return self._path_for(digest).exists()
