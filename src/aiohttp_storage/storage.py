import asyncio
import os
import re
import unicodedata
from abc import ABCMeta, abstractmethod
from functools import cached_property, partial, wraps
from io import BufferedIOBase
from pathlib import Path
from secrets import choice
from string import ascii_letters, digits
from typing import Awaitable, Callable, ParamSpec, TypeVar

import aiofiles
import aiofiles.os
import aiofiles.ospath
from aiohttp import web

RANDOM_STRING_CHARS = ascii_letters + digits

P = ParamSpec("P")
T = TypeVar("T")

FILE_STORAGE_APP_KEY = "file_storage"


class SuspiciousFileOperation(ValueError):
    ...


def get_valid_filename(name: str) -> str:
    s = str(name).strip().replace(" ", "_")
    s = unicodedata.normalize("NFKD", s)
    s = re.sub(r"[^\w.-]", "", s)
    if s in {"", ".", ".."}:
        raise SuspiciousFileOperation(f"Could not derive file name from '{name}'")
    return s


def safe_join(base: str | Path, *path: str | Path) -> str:
    base_path = Path(base).resolve()
    joined_path = base_path.joinpath(*path).resolve()
    if not joined_path.is_relative_to(base_path):
        raise SuspiciousFileOperation(
            f"Path {joined_path} is not subpath of {base_path}"
        )
    return str(joined_path)


def validate_file_name(filename: str | Path, allow_relative_path=False):
    # Remove potentially dangerous names
    path = Path(filename)
    if path.name in {"", ".", ".."}:
        raise SuspiciousFileOperation(f"Could not derive file name from '{filename}'")

    if allow_relative_path:
        if path.is_absolute() or ".." in path.parts:
            raise SuspiciousFileOperation(
                f"Detected path traversal attempt in {filename}"
            )
    elif path.parts[0] != path.name:
        raise SuspiciousFileOperation(f"File name '{filename}' includes path elements")

    return filename


def run_async(func: Callable[P, T]) -> Callable[P, Awaitable[T]]:
    @wraps(func)
    async def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, partial(func, *args, **kwargs))

    return wrapper


class AbstractStorage(metaclass=ABCMeta):
    @abstractmethod
    async def save(self, filename: str, data: BufferedIOBase, max_len: int = 0) -> str:
        ...

    @abstractmethod
    async def exists(self, filename: str) -> bool:
        ...

    @abstractmethod
    async def get_available_filename(self, filename: str, max_len: int = 0) -> str:
        ...

    @abstractmethod
    def get_alternative_stem(self, stem: str) -> str:
        ...

    @abstractmethod
    async def url(self, filename: str) -> str:
        ...

    @abstractmethod
    async def delete(self, filename: str):
        ...


class BaseStorage(AbstractStorage):
    async def save(self, filename: str, data: BufferedIOBase, max_len: int = 0) -> str:
        filename = await self.get_available_filename(filename, max_len)
        filename = await self._save(filename, data)
        validate_file_name(filename, allow_relative_path=True)
        return filename

    async def get_available_filename(self, filename: str, max_len: int = 0) -> str:
        origin_path = Path(filename)
        if ".." in origin_path.parts:
            raise SuspiciousFileOperation(
                f"Detected path traversal '{origin_path.parent}'"
            )
        validate_file_name(origin_path.name)
        while await self.exists(filename) or (max_len > 0 and len(filename) > max_len):
            filename = str(
                origin_path.with_stem(self.get_alternative_stem(origin_path.stem))
            )
            if max_len <= 0:
                continue
            truncation = len(filename) - max_len
            if truncation > 0:
                print(origin_path)
                truncated_stem = origin_path.stem[:-truncation]
                if not truncated_stem:
                    raise SuspiciousFileOperation(
                        f"Storage can not find an available filename for '{origin_path}'."
                    )
                filename = str(
                    origin_path.with_stem(self.get_alternative_stem(truncated_stem))
                )
        return filename

    def get_alternative_stem(self, stem: str, random_length=7, sep="_") -> str:
        s = "".join([choice(RANDOM_STRING_CHARS) for i in range(random_length)])
        return f"{stem}{sep}{s}"

    async def _save(self, filename: str, data: BufferedIOBase) -> str:
        raise NotImplementedError

    async def exists(self, filename: str) -> bool:
        raise NotImplementedError

    async def delete(self, filename: str):
        raise NotImplementedError

    async def url(self, filename: str) -> str:
        raise NotImplementedError


class FileSystemStorage(BaseStorage):
    def __init__(self, location: str | Path, base_url: str | None = None):
        self._location = location
        self._base_url = base_url

    @cached_property
    def location(self) -> Path:
        return Path(self._location).resolve()

    @cached_property
    def base_url(self) -> str:
        if not self._base_url:
            raise ValueError("Invalid base_url")
        return self._base_url.rstrip("/")

    async def exists(self, filename: str) -> bool:
        dst_path = safe_join(self.location, filename)
        return await run_async(os.path.lexists)(dst_path)

    async def _save(self, filename: str, data: BufferedIOBase) -> str:
        print(filename)
        dst_path = Path(safe_join(self.location, filename))
        try:
            await aiofiles.os.makedirs(dst_path.parent, exist_ok=True)
        except FileExistsError:
            raise FileExistsError(f"{dst_path.parent} exists and its not a directory")
        while True:
            try:
                async with aiofiles.open(dst_path, "xb") as fd:
                    await fd.write(data.read())

            except FileExistsError:
                print("exists")
                filename = await self.get_available_filename(filename)
                dst_path = Path(safe_join(self.location, filename))
            else:
                break

        return filename

    async def url(self, filename: str) -> str:
        validate_file_name(filename, allow_relative_path=True)
        return f"{self.base_url}/{filename.lstrip('/')}"

    async def delete(self, filename: str):
        if await self.exists(filename):
            await aiofiles.os.unlink(safe_join(self.location, filename))


def setup(app: web.Application, storage: AbstractStorage):
    app[FILE_STORAGE_APP_KEY] = storage


def get_storage(request: web.Request) -> AbstractStorage:
    try:
        return request.config_dict[FILE_STORAGE_APP_KEY]
    except KeyError:
        raise RuntimeError("You must set up file storage first")


async def save_file(
    request: web.Request, filename: str, data: BufferedIOBase, max_len=0
) -> str:
    return await get_storage(request).save(filename, data, max_len)


async def delete_file(request: web.Request, filename: str):
    await get_storage(request).delete(filename)


async def file_exists(request: web.Request, filename: str) -> bool:
    return await get_storage(request).exists(filename)


async def file_url(request: web.Request, filename: str) -> str:
    return await get_storage(request).url(filename)
