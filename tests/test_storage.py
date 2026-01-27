import os
import shutil
import sys
import unittest
from io import BytesIO
from unittest.mock import AsyncMock


sys.path.append("./src")
from aiohttp_storage.storage import (
    BaseStorage,
    FileSystemStorage,
    SuspiciousFileOperation,
    get_valid_filename,
    safe_join,
)


class TestBaseStorage(unittest.IsolatedAsyncioTestCase):
    filename = "some_file.txt"

    def exist_side_effect(self, name, dst_path=None):
        if name == self.filename:
            return True

    def setUp(self) -> None:
        self.storage = BaseStorage()
        self.storage.exists = AsyncMock(side_effect=self.exist_side_effect)

    async def test_available_name(self):
        filename = await self.storage.get_available_filename(self.filename)
        self.assertNotEqual(self.filename, filename)
        self.assertEqual(len(self.filename) + 8, len(filename))

    def test_valid_filename(self):
        self.assertEqual("test_some_file.jpg", get_valid_filename("test some file.jpg"))


class TestFileSystemStorage(unittest.IsolatedAsyncioTestCase):
    location_dir = "test_storage"

    def setUp(self):
        self.storage = FileSystemStorage(self.location_dir)
        self.storage.location.mkdir(exist_ok=True)

    def tearDown(self) -> None:
        shutil.rmtree(self.storage.location)

    async def test_save_file(self):
        content = BytesIO(b"Some initial bytes")
        filename = "sample_filename.txt"
        filename_0 = await self.storage.save(filename, content)
        self.assertEqual(filename, filename_0)
        self.assertTrue(await self.storage.exists(filename_0))
        filename_1 = await self.storage.save(filename, content)
        self.assertTrue(await self.storage.exists(filename_1))
        self.assertFalse(await self.storage.exists("file_doesnt_exists.txt"))
        self.assertNotEqual(filename_0, filename_1)
        await self.storage.delete(filename_0)
        await self.storage.delete(filename_1)
        self.assertFalse(await self.storage.exists(filename_0))
        self.assertFalse(await self.storage.exists(filename_1))
    async def test_rmdir(self):
        content = BytesIO(b"Some initial bytes")
        for i in range(5):
            filename = f"test_dir/filename{i}.txt"
            await self.storage.save(filename, content)
            self.assertTrue(await self.storage.exists(filename))
        self.assertTrue(await self.storage.exists("test_dir"))
        with self.assertRaises(OSError):
            await self.storage.remove_directory("test_dir")
        await self.storage.remove_directory("test_dir", recursive=True)
        self.assertFalse(await self.storage.exists("test_dir"))


class SafeJoinTests(unittest.TestCase):
    def test_base_path_ends_with_sep(self):
        drive, path = os.path.splitdrive(safe_join("/abc/", "abc"))
        self.assertEqual(path, "{0}abc{0}abc".format(os.path.sep))

    def test_root_path(self):
        drive, path = os.path.splitdrive(safe_join("/", "path"))
        self.assertEqual(
            path,
            "{}path".format(os.path.sep),
        )

        drive, path = os.path.splitdrive(safe_join("/", ""))
        self.assertEqual(
            path,
            os.path.sep,
        )

    def test_parent_path(self):
        with self.assertRaises(SuspiciousFileOperation):
            safe_join("/abc/", "../def")
