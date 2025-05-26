import yaml

import dagger
from dagger import function, object_type

from .cli import Cli


@object_type
class Config:
    """Apko Config"""

    config: dagger.File
    workdir: dagger.Directory | None = None

    apko: Cli

    @function
    def file(self) -> dagger.File:
        """Returns the full Apko config file"""
        container: dagger.Container = self.apko.container().with_mounted_file(
            "/tmp/apko.yaml",
            source=self.config,
            owner=self.apko.user,
        )
        if self.workdir:
            container = container.with_mounted_directory(
                "$APKO_WORK_DIR", source=self.workdir, owner=self.apko.user, expand=True
            )
        cmd: list[str] = [
            "apko",
            "show-config",
            "/tmp/apko.yaml",
            "--log-level",
            "ERROR",
        ]
        return container.with_exec(cmd, redirect_stdout="/tmp/stdout").file(
            "/tmp/stdout"
        )

    @function
    async def authors(self) -> list[str]:
        """Returns the authors from 'org.opencontainers.image.authors' annotation"""
        config_dict: dict = yaml.safe_load(await self.file().contents())
        licenses: str = config_dict["annotations"]["org.opencontainers.image.authors"]
        return licenses.split(",")

    @function
    async def title(self) -> str:
        """Returns the title from 'org.opencontainers.image.title' annotation"""
        config_dict: dict = yaml.safe_load(await self.file().contents())
        return config_dict["annotations"]["org.opencontainers.image.title"].strip()

    @function
    async def description(self) -> str:
        """Returns the description from 'org.opencontainers.image.description' annotation"""
        config_dict: dict = yaml.safe_load(await self.file().contents())
        return config_dict["annotations"][
            "org.opencontainers.image.description"
        ].strip()

    @function
    async def source(self) -> str:
        """Returns the source from 'org.opencontainers.image.source' annotation"""
        config_dict: dict = yaml.safe_load(await self.file().contents())
        return config_dict["annotations"]["org.opencontainers.image.source"].strip()

    @function
    async def version(self) -> str:
        """Returns the version from 'org.opencontainers.image.version' annotation"""
        config_dict: dict = yaml.safe_load(await self.file().contents())
        return config_dict["annotations"]["org.opencontainers.image.version"].strip()

    @function
    async def vendor(self) -> str:
        """Returns the vendor from 'org.opencontainers.image.vendor' annotation"""
        config_dict: dict = yaml.safe_load(self.file().contents())
        return config_dict["annotations"]["org.opencontainers.image.vendor"].strip()

    @function
    async def licenses(self) -> list[str]:
        """Returns the licenses from 'org.opencontainers.image.licenses' annotation"""
        config_dict: dict = yaml.safe_load(await self.file().contents())
        licenses: str = config_dict["annotations"]["org.opencontainers.image.licenses"]
        return licenses.split(",")

    @function
    async def platforms(self) -> list[dagger.Platform]:
        """Returns the platforms"""
        platforms: list[dagger.Platform] = []
        config_dict: dict = yaml.safe_load(await self.file().contents())
        archs: list[str] = config_dict.get("archs", [])
        for arch in archs:
            if arch in ["amd64", "x86_64"]:
                platforms.append(dagger.Platform("linux/amd64"))
            elif arch in ["arm64", "aarch64"]:
                platforms.append(dagger.Platform("linux/arm64"))
            else:
                continue
        return platforms
