import logging
from logging import Logger
from pathlib import Path

import pygit2

from nvd_severity.log import LOGGER


class Git:
    repo: pygit2.Repository

    def __init__(
            self,
            repo_path: Path,
            token: str,
            user_name: str,
            user_email: str,
            logger: Logger = LOGGER.getChild("Git")
    ):
        self._repo_path = repo_path
        self._token = token
        self._user_name = user_name
        self._logger = logger
        self._author = pygit2.Signature(user_name, user_email)

    def clone(self, url, remote_url=None):
        self.repo = pygit2.clone_repository(url, self._repo_path)

        self.repo.remotes.set_url("origin", remote_url or url)

        repo_url = self.repo.remotes[0].url
        self.repo.remotes.set_url('origin', repo_url)
        self.repo.remotes.set_push_url('origin', repo_url)

    def checkout(self, branch_name="main"):
        branch = self.repo.branches.local.get(branch_name)
        if branch is None:
            branch = self.repo.create_branch(branch_name, self.repo.head.peel())

        ref = self.repo.lookup_reference(branch.name)

        self.repo.checkout(ref)
        self._logger.info(f"Checkout to {branch_name} branch")

    def add(self, path=None):
        self.repo.index.add_all([path] or [])
        self.repo.index.write()

    def commit(self, message):
        ref = self.repo.head.name
        parents = [self.repo.head.target]

        tree = self.repo.index.write_tree()
        oid = self.repo.create_commit(
            ref, self._author, self._author, message, tree, parents
        )

        self.repo.head.set_target(oid)

    def push(self):
        remote = self.repo.remotes["origin"]
        credentials = pygit2.UserPass(self._user_name, self._token)
        remote.credentials = credentials
        callbacks = pygit2.RemoteCallbacks(credentials=credentials)
        remote.push([self.repo.head.name], callbacks=callbacks)

