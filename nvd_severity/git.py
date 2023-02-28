from logging import Logger
from pathlib import Path

import sh

from nvd_severity.log import LOGGER


class Git:
    def __init__(
            self,
            repo_path: Path,
            user_name: str,
            user_email: str,
            logger: Logger = LOGGER.getChild("Git")
    ):
        self._repo_path = repo_path
        self._user_name = user_name
        self._user_email = user_email
        self._logger = logger

    def _git(self, *args):
        sh.git(*self._generate_git_args(self._repo_path), args)

    def clone(self, url, local: bool = False, remote_url=None):
        if local:
            sh.git("clone", "-v", "--progress", "--single-branch", "--", url, self._repo_path)
        else:
            sh.git("clone", "-v", "--progress", "--single-branch", "--depth=1", "--", url, self._repo_path)
        self._git("remote", "set-url", "origin", remote_url or url)
        self._git("config", "user.name", f'{self._user_name}')
        self._git("config", "user.email", f'{self._user_email}')

    def checkout(self, branch):
        self._git("checkout", "-b", branch)

    def commit(self, path, message):
        self._git("add", "-f", path)
        self._git("commit", "--message", message)

    def push(self, branch="main"):
        self._git("push", "origin", branch)

    @classmethod
    def _generate_git_args(cls, repo_path: Path):
        git_dir = repo_path / ".git"
        return ["--git-dir", git_dir, "--work-tree", repo_path]
