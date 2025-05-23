from typing import Annotated, Self
import os
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
        user: Annotated[str | None, Doc("Image user")] = "0",
        signing_key: Annotated[dagger.Secret | None, Doc("Signing key")] = None,
    ):
        """Constructor"""
        return cls(
            image=image,
            version=version,
            user=user,
            signing_key_=signing_key,
            public_key_=None,
            container_=None,
        )

    @function
    def container(self) -> dagger.Container:
        """Returns container"""
        if self.container_:
            return self.container_

        container: dagger.Container = dag.container()
        pkg = "melange"
        if self.version != "latest":
            pkg = f"{pkg}~{self.version}"

        self.container_ = (
            container.from_(address=self.image)
            .with_user("0")
            .with_exec(["apk", "add", "--no-cache", "melange"])
            .with_entrypoint(["/usr/bin/melange"])
            .with_user(self.user)
            .with_env_variable("MELANGE_CACHE_DIR", "/tmp/cache")
            .with_env_variable("MELANGE_APK_CACHE_DIR", "/tmp/apk-cache")
            .with_env_variable("MELANGE_WORK_DIR", "/tmp/work")
            .with_env_variable("MELANGE_KEYRING_DIR", "/tmp/keyring")
            .with_env_variable("MELANGE_SIGNING_KEY", "/tmp/keyring/melange.rsa")
            .with_env_variable("MELANGE_OUTPUT_DIR", "/tmp/output")
            .with_env_variable("MELANGE_SRC_DIR", "/tmp/src")
            .with_exec(
                ["mkdir", "-p", "$MELANGE_KEYRING_DIR"],
                use_entrypoint=False,
                expand=True,
            )
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
        )

        return self.container_

    @function
    async def keygen(
        self,
        key_size: Annotated[
            int | None, Doc("the size of the prime to calculate ")
        ] = 4096,
    ) -> dagger.Directory:
        """Generate a key for package signing"""
        cmd = ["keygen", "--key-size", str(key_size), "$MELANGE_SIGNING_KEY"]

        self.container_ = self.container().with_exec(
            cmd, use_entrypoint=True, expand=True
        )
        signing_key_file: dagger.File = self.container().file(
            "$MELANGE_SIGNING_KEY", expand=True
        )
        self.signing_key_ = dag.set_secret(
            name="signing_key", plaintext=await signing_key_file.contents()
        )
        self.public_key_ = self.container().file(
            "$MELANGE_SIGNING_KEY.pub", expand=True
        )
        return self.container().directory("$MELANGE_KEYRING_DIR", expand=True)

    @function
    async def with_keygen(
        self,
        key_size: Annotated[
            int | None, Doc("the size of the prime to calculate ")
        ] = 4096,
    ) -> Self:
        """Generate a key for package signing for chaining"""
        await self.keygen(key_size=key_size)
        return self

    @function
    async def signing_key(self) -> dagger.File:
        """Return the generated signing key"""
        return dag.file(
            name="signing_key", contents=await self.signing_key_.plaintext()
        )

    @function
    def public_key(self) -> dagger.File:
        """Return the generated public key"""
        return self.public_key_

    @function
    async def bump(
        self,
        config: Annotated[dagger.File, Doc("Config file")],
        version: Annotated[str, Doc("Version to bump to")],
    ) -> dagger.File:
        """Update a Melange YAML file to reflect a new package version"""
        config_name = await config.name()

        melange = self.container().with_mounted_file(
            path=os.path.join("$MELANGE_WORK_DIR", config_name),
            source=config,
            owner=self.user,
            expand=True,
        )

        cmd = ["bump", config_name, version]

        self.container_ = melange.with_exec(cmd, use_entrypoint=True, expand=True)
        return self.container_.file(
            os.path.join("$MELANGE_WORK_DIR", config_name), expand=True
        )

    @function
    async def with_bump(
        self,
        config: Annotated[dagger.File, Doc("Config file")],
        version: Annotated[str, Doc("Version to bump to")],
    ) -> Self:
        """Update a Melange YAML file to reflect a new package version for chaining"""
        await self.bump(config=config, version=version)
        return self

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
        ] = None,
    ) -> dagger.Directory:
        """Build a package from a YAML configuration file"""
        config_name = await config.name()

        melange = self.container().with_mounted_file(
            path=os.path.join("$MELANGE_WORK_DIR", config_name),
            source=config,
            owner=self.user,
            expand=True,
        )

        if version:
            melange = melange.with_exec(
                ["bump", config_name, version], use_entrypoint=True, expand=True
            )

        if signing_key:
            self.signing_key_ = signing_key
            self.public_key_ = None
        else:
            if self.signing_key_ is None:
                await self.keygen()

        melange = melange.with_mounted_secret(
            path="$MELANGE_SIGNING_KEY",
            source=self.signing_key_,
            owner=self.user,
            expand=True,
        )

        cmd = [
            "build",
            config_name,
            "--apk-cache-dir",
            "$MELANGE_APK_CACHE_DIR",
            "--cache-dir",
            "$MELANGE_CACHE_DIR",
            "--signing-key",
            "$MELANGE_SIGNING_KEY",
            "--out-dir",
            "$MELANGE_OUTPUT_DIR",
        ]

        if source_dir:
            melange = melange.with_mounted_directory(
                "$MELANGE_SRC_DIR", source=source_dir, owner=self.user, expand=True
            )
            cmd.extend(["--source-dir", "$MELANGE_SRC_DIR"])

        for arch in archs or [await dag.default_platform()]:
            cmd.extend(["--arch", arch.split("/")[1]])

        self.container_ = melange.with_exec(
            cmd, insecure_root_capabilities=True, use_entrypoint=True, expand=True
        )

        output_dir: dagger.Directory = self.container_.directory(
            "$MELANGE_OUTPUT_DIR", expand=True
        )
        if self.public_key_:
            return output_dir.with_file(
                "melange.rsa.pub", self.public_key_, permissions=0o644
            )
        return output_dir

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
        ] = None,
    ) -> Self:
        """Build a package from a YAML configuration file (for chaining)"""
        await self.build(
            config=config, version=version, signing_key=signing_key, archs=archs
        )
        return self
