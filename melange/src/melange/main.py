from typing import Annotated, Self

import dagger
from dagger import Doc, Name, dag, function, object_type

from .signing_key import SigningKey


@object_type
class Melange:
    """Melange"""

    image: str
    version: str
    user: str

    signing_key_: SigningKey | None = None

    container_: dagger.Container | None = None

    @classmethod
    async def create(
        cls,
        image: Annotated[str | None, Doc("wolfi-base image")] = (
            "cgr.dev/chainguard/wolfi-base:latest"
        ),
        version: Annotated[str | None, Doc("Melange version")] = "0.35.1",
        user: Annotated[str | None, Doc("Image user")] = "65532",
    ):
        """Constructor"""
        return cls(
            image=image,
            version=version,
            user=user,
        )

    def _signing_key(
        self,
        name: Annotated[str | None, Doc("Key name")] = "melange.rsa",
        private: Annotated[dagger.Secret | None, Doc("private key")] = None,
    ) -> SigningKey:
        """Signing key functions"""
        return SigningKey(
            container=self.container(), user=self.user, name=name, private=private
        )

    @function
    def container(self) -> dagger.Container:
        """Returns melange container"""
        if self.container_:
            return self.container_

        container: dagger.Container = dag.container()
        pkg = "melange"
        if self.version != "latest":
            pkg = f"{pkg}~{self.version}"

        self.container_ = (
            container.from_(address=self.image)
            .with_user("0")
            .with_exec(["apk", "add", "--no-cache", "openssl", pkg])
            .with_env_variable("MELANGE_CACHE_DIR", "/cache/melange")
            .with_env_variable("MELANGE_APK_CACHE_DIR", "/cache/apk")
            .with_env_variable("MELANGE_WORK_DIR", "/melange")
            .with_mounted_cache(
                "$MELANGE_CACHE_DIR",
                dag.cache_volume("MELANGE_CACHE"),
                sharing=dagger.CacheSharingMode("SHARED"),
                owner=self.user,
                expand=True,
            )
            .with_mounted_cache(
                "$MELANGE_APK_CACHE_DIR",
                dag.cache_volume("MELANGE_APK_CACHE"),
                sharing=dagger.CacheSharingMode("SHARED"),
                owner=self.user,
                expand=True,
            )
            .with_user(self.user)
            .with_workdir("$MELANGE_WORK_DIR", expand=True)
            .with_entrypoint(["/usr/bin/melange"])
        )

        return self.container_

    @function
    def keygen(
        self,
        name: Annotated[str | None, Doc("Key name")] = "melange.rsa",
        key_size: Annotated[
            int | None, Doc("the size of the prime to calculate ")
        ] = 4096,
    ) -> dagger.Directory:
        """Generate a key pair for package signing"""
        return self._signing_key().generate(name=name, size=key_size)

    @function
    async def with_keygen(
        self,
        name: Annotated[str | None, Doc("Key name")] = "melange.rsa",
        key_size: Annotated[
            int | None, Doc("the size of the prime to calculate ")
        ] = 4096,
    ) -> Self:
        """Generate a key for package signing (for chaining)"""
        self.signing_key_ = await self._signing_key().with_generate(
            name=name, size=key_size
        )
        self.container_ = self.container().with_mounted_secret(
            f"/tmp/{name}", self.signing_key_.private, owner=self.user
        )
        return self

    @function
    def with_signing_key(
        self,
        key: Annotated[dagger.Secret, Doc("Key to use for signing")],
        name: Annotated[str | None, Doc("Key name")] = "melange.rsa",
    ) -> Self:
        """Include the specified signing key (for chaining)"""
        self.signing_key_ = self._signing_key(name=name, private=key)
        self.container_ = self.container().with_mounted_secret(
            f"/tmp/{name}", self.signing_key_.private, owner=self.user
        )
        return self

    @function
    def has_signing_key(self) -> bool:
        """Check if signing key is present"""
        if self.signing_key_:
            return True
        return False

    @function
    def public_key(self) -> dagger.File:
        """Returns the public key"""
        return self.signing_key_.public()

    @function
    def bump(
        self,
        config: Annotated[dagger.File, Doc("Config file")],
        version: Annotated[str, Doc("Version to bump to")],
    ) -> dagger.File:
        """Update a Melange YAML file to reflect a new package version"""
        cmd = ["bump", "melange.yaml", version]
        return (
            self.container()
            .with_file(
                path="melange.yaml",
                source=config,
                owner=self.user,
            )
            .with_exec(cmd, use_entrypoint=True)
            .file("melange.yaml")
        )

    @function
    async def build(
        self,
        config: Annotated[dagger.File, Doc("Config file")],
        version: Annotated[str | None, Doc("Version to bump to")] = "",
        source_dir: Annotated[
            dagger.Directory | None, Doc("Directory used for included sources")
        ] = None,
        signing_key: Annotated[
            dagger.Secret | None, Doc("Key to use for signing")
        ] = None,
        archs: Annotated[
            list[dagger.Platform] | None, Doc("Target architectures"), Name("arch")
        ] = (),
    ) -> dagger.Directory:
        """Build a package from a YAML configuration file"""
        if not archs:
            archs = [await self.container().platform()]

        if signing_key is None and self.signing_key_ is None:
            raise TypeError("You must provide a signing key to proceed.")

        container: dagger.Container = self.container().with_file(
            path="melange.yaml",
            source=config,
            owner=self.user,
        )

        if version:
            container = container.with_exec(
                ["bump", "melange.yaml", version], use_entrypoint=True
            )

        if signing_key:
            self.signing_key_ = self._signing_key(private=signing_key)
            container = container.with_mounted_secret(
                f"/tmp/{self.signing_key_.name}",
                self.signing_key_,
                owner=self.user,
            )

        cmd = [
            "build",
            "melange.yaml",
            "--signing-key",
            f"/tmp/{self.signing_key_.name}",
            "--apk-cache-dir",
            "$MELANGE_APK_CACHE_DIR",
            "--cache-dir",
            "$MELANGE_CACHE_DIR",
            "--out-dir",
            "packages",
        ]

        if source_dir:
            container = container.with_mounted_directory(
                "/tmp/source",
                source=source_dir,
                owner=self.user,
            )
            cmd.extend(["--source-dir", "/tmp/source"])

        for arch in archs:
            cmd.extend(["--arch", arch.split("/")[1]])

        return (
            container.with_user("0")
            .with_exec(
                cmd, insecure_root_capabilities=True, use_entrypoint=True, expand=True
            )
            .with_user(self.user)
            .directory(
                "packages",
            )
            .with_file(
                f"{self.signing_key_.name}.pub",
                self.signing_key_.public(),
                permissions=0o644,
            )
        )

    @function
    async def with_build(
        self,
        config: Annotated[dagger.File, Doc("Config file")],
        version: Annotated[str | None, Doc("Version to bump to")] = "",
        signing_key: Annotated[
            dagger.Secret | None, Doc("Key to use for signing")
        ] = None,
        archs: Annotated[
            list[dagger.Platform] | None, Doc("Target architectures"), Name("arch")
        ] = (),
    ) -> Self:
        """Build a package from a YAML configuration file (for chaining)"""
        packages: dagger.Directory = await self.build(
            config=config, version=version, signing_key=signing_key, archs=archs
        )
        self.container_ = self.container().with_directory(
            "packages", packages, owner=self.user
        )
        return self
