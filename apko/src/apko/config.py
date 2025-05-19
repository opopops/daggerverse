import yaml

import dagger
from dagger import function, object_type

from .cli import Cli


@object_type
class Config:
    """Apko Config"""

    workdir: dagger.Directory
    config: dagger.File

    apko: Cli

    @function
    def file(self) -> dagger.File:
        """Returns the full Apko config file"""
        return (
            self.apko.container()
            .with_mounted_file(
                "$APKO_CONFIG_FILE",
                source=self.config,
                owner=self.apko.user,
                expand=True,
            )
            .with_exec(
                ["apko", "show-config", "$APKO_CONFIG_FILE", "--log-level", "ERROR"],
                redirect_stdout="/tmp/config.yaml",
                expand=True,
            )
            .file("/tmp/config.yaml")
        )

    @function
    async def authors(self) -> list[str]:
        """Returns the authors from 'org.opencontainers.image.authors' annotation"""
        config_dict: dict = yaml.safe_load(self.file().contents())
        licenses: str = config_dict["annotations"]["org.opencontainers.image.authors"]
        return licenses.split(",")

    @function
    async def title(self) -> str:
        """Returns the title from 'org.opencontainers.image.title' annotation"""
        config_dict: dict = yaml.safe_load(self.file().contents())
        return config_dict["annotations"]["org.opencontainers.image.title"]

    @function
    async def description(self) -> str:
        """Returns the description from 'org.opencontainers.image.description' annotation"""
        config_dict: dict = yaml.safe_load(self.file().contents())
        return config_dict["annotations"]["org.opencontainers.image.title"]

    @function
    async def source(self) -> str:
        """Returns the source from 'org.opencontainers.image.source' annotation"""
        config_dict: dict = yaml.safe_load(self.file().contents())
        return config_dict["annotations"]["org.opencontainers.image.source"]

    @function
    async def version(self) -> str:
        """Returns the version from 'org.opencontainers.image.version' annotation"""
        config_dict: dict = yaml.safe_load(self.file().contents())
        return config_dict["annotations"]["org.opencontainers.image.version"]

    @function
    async def vendor(self) -> str:
        """Returns the vendor from 'org.opencontainers.image.vendor' annotation"""
        config_dict: dict = yaml.safe_load(self.file().contents())
        return config_dict["annotations"]["org.opencontainers.image.vendor"]

    @function
    async def licenses(self) -> list[str]:
        """Returns the licenses from 'org.opencontainers.image.licenses' annotation"""
        config_dict: dict = yaml.safe_load(self.file().contents())
        licenses: str = config_dict["annotations"]["org.opencontainers.image.licenses"]
        return licenses.split(",")

    @function
    async def platforms(self) -> list[dagger.Platform]:
        """Returns the platforms"""
        platforms: list[dagger.Platform] = []
        config_dict: dict = yaml.safe_load(self.file().contents())
        archs: list[str] = config_dict.get("archs", [])
        for arch in archs:
            if arch in ["amd64", "x86_64"]:
                platforms.append(dagger.Platform("linux/amd64"))
            elif arch in ["arm64", "aarch64"]:
                platforms.append(dagger.Platform("linux/arm64"))
            else:
                continue
        return platforms
