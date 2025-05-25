from typing import Annotated, Self

import dagger
from dagger import Doc, Name, dag, function, object_type


@object_type
class Melange:
    """Melange"""

    image: str
    version: str
    user: str
    signing_key_: dagger.Secret | None
    public_key_: dagger.File | None
    container_: dagger.Container | None

    @classmethod
    async def create(
        cls,
        image: Annotated[str | None, Doc("wolfi-base image")] = (
            "cgr.dev/chainguard/wolfi-base:latest"
        ),
        version: Annotated[str | None, Doc("Melange version")] = "latest",
        user: Annotated[str | None, Doc("Image user")] = "65532",
    ):
        """Constructor"""
        return cls(
            image=image,
            version=version,
            user=user,
            signing_key_=None,
            public_key_=None,
            container_=None,
        )

    def _public_key(self, signing_key: dagger.Secret) -> dagger.File:
        """Return the public key from the specified secret key"""
        return (
            self.container()
            .with_mounted_secret(
                "/tmp/melange.rsa",
                source=signing_key,
                owner=self.user,
            )
            .with_exec(
                [
                    "openssl",
                    "rsa",
                    "-in",
                    "/tmp/melange.rsa",
                    "-pubout",
                    "-out",
                    "melange.rsa.pub",
                ],
            )
            .file("melange.rsa.pub")
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
            .with_entrypoint(["/usr/bin/melange"])
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
            .with_workdir("$MELANGE_WORK_DIR", expand=True)
            .with_user(self.user)
        )

        return self.container_

    @function
    def keygen(
        self,
        key_size: Annotated[
            int | None, Doc("the size of the prime to calculate ")
        ] = 4096,
    ) -> dagger.Directory:
        """Generate a key pair for package signing"""
        cmd = ["keygen", "--key-size", str(key_size), "melange.rsa"]
        return (
            self.container()
            .with_exec(cmd, use_entrypoint=True, expand=True)
            .directory(".")
        )

    @function
    async def with_keygen(
        self,
        key_size: Annotated[
            int | None, Doc("the size of the prime to calculate ")
        ] = 4096,
    ) -> Self:
        """Generate a key pair for package signing for chaining (for testing purpose)"""
        keys_dir: dagger.Directory = self.keygen(key_size=key_size)
        self.signing_key_ = dag.set_secret(
            "melange.rsa", await keys_dir.file("melange.rsa").contents()
        )
        self.public_key_ = keys_dir.file("melange.rsa.pub")
        self.container_ = self.container().with_mounted_secret(
            "/tmp/melange.rsa", self.signing_key_, owner=self.user
        )
        return self

    @function
    def signing_key(self) -> dagger.Secret:
        """Return the signing key"""
        return self.signing_key_

    @function
    def with_signing_key(
        self,
        signing_key: Annotated[dagger.Secret, Doc("Key to use for signing")],
    ) -> Self:
        """Include the specified signing key (for chaining)"""
        self.signing_key_ = signing_key
        self.public_key_ = self._public_key(signing_key)
        self.container_ = self.container().with_mounted_secret(
            "/tmp/melange.rsa", self.signing_key_, owner=self.user
        )
        return self

    @function
    def public_key(self) -> dagger.File:
        """Return the public key"""
        if self.public_key_:
            return self.public_key_
        self.public_key_ = self._public_key(self.signing_key_)
        return self.public_key_

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
    def build(
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
            self.signing_key_ = signing_key
            self.public_key_ = self._public_key(signing_key)
        container = container.with_mounted_secret(
            "/tmp/melange.rsa", self.signing_key_, owner=self.user
        )

        cmd = [
            "build",
            "melange.yaml",
            "--signing-key",
            "/tmp/melange.rsa",
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
            .with_file("melange.rsa.pub", self.public_key_, permissions=0o644)
        )

    @function
    def with_build(
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
        packages: dagger.Directory = self.build(
            config=config, version=version, signing_key=signing_key, archs=archs
        )
        self.container_ = self.container().with_directory(
            "packages", packages, owner=self.user
        )
        return self
