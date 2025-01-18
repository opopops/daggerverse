from typing import Annotated, Self
import dagger
from dagger import Doc, dag, function, field, object_type


@object_type
class Melange:
    image: Annotated[str, Doc("Melange image")] = field(
        default="cgr.dev/chainguard/melange:latest-dev"
    )
    registry_username: Annotated[str, Doc("Registry username")] | None = field(
        default=None
    )
    registry_password: Annotated[dagger.Secret, Doc("Registry password")] | None = (
        field(default=None)
    )
    user: Annotated[str, Doc("image user")] | None = field(default="0")

    container_: dagger.Container | None = None

    private_key_: dagger.File | None = None
    public_key_: dagger.File | None = None

    @function
    def container(self) -> dagger.Container:
        """Returns container"""
        if self.container_:
            return self.container_

        container: dagger.Container = dag.container()
        if self.registry_username is not None and self.registry_password is not None:
            container = container.with_registry_auth(
                address=self.image,
                username=self.registry_username,
                secret=self.registry_password,
            )
        self.container_ = (
            container.from_(address=self.image)
            .with_user(self.user)
            .with_env_variable("MELANGE_CACHE_DIR", "/tmp/cache")
            .with_env_variable("MELANGE_APK_CACHE_DIR", "/tmp/apk-cache")
            .with_env_variable("MELANGE_WORK_DIR", "/tmp/work")
            .with_env_variable("MELANGE_SIGNING_KEY", "/tmp/melange.rsa")
            .with_env_variable("MELANGE_OUTPUT_DIR", "/tmp/packages")
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
    def keygen(
        self,
        key_size: Annotated[int, Doc("the size of the prime to calculate ")] = 4096,
    ) -> tuple[dagger.File]:
        """Generate a key for package signing"""
        cmd = [
            "keygen",
            "--key-size",
            str(key_size),
            "$MELANGE_SIGNING_KEY",
        ]

        self.container_ = self.container().with_exec(
            cmd, use_entrypoint=True, expand=True
        )
        self.private_key_ = self.container().file("$MELANGE_SIGNING_KEY", expand=True)
        self.public_key_ = self.container().file(
            "$MELANGE_SIGNING_KEY.pub", expand=True
        )

        return (self.private_key_, self.public_key_)

    @function
    def with_keygen(
        self,
        key_size: Annotated[int, Doc("the size of the prime to calculate ")] = 4096,
    ) -> Self:
        """Generate a key for package signing for chaining"""
        self.keygen(key_size=key_size)
        return self

    @function
    def build(
        self,
        config: Annotated[dagger.File, Doc("Config file")],
        signing_key: Annotated[dagger.File, Doc("Key to use for signing")]
        | None = None,
        arch: Annotated[str, Doc("Architectures to build for")] | None = None,
    ) -> dagger.Directory:
        """Build a package from a YAML configuration file"""
        melange = self.container().with_mounted_file(
            path="$MELANGE_WORK_DIR/melange.yaml",
            source=config,
            owner=self.user,
            expand=True,
        )

        if signing_key is None:
            signing_key, _ = self.keygen()

        melange = melange.with_mounted_file(
            path="$MELANGE_SIGNING_KEY",
            source=signing_key,
            owner=self.user,
            expand=True,
        )

        cmd = [
            "build",
            "melange.yaml",
            "--apk-cache-dir",
            "$MELANGE_APK_CACHE_DIR",
            "--cache-dir",
            "$MELANGE_CACHE_DIR",
            "--signing-key",
            "$MELANGE_SIGNING_KEY",
            "--out-dir",
            "$MELANGE_OUTPUT_DIR",
        ]

        if arch:
            cmd.extend(["--arch", arch])

        self.container_ = melange.with_exec(
            cmd,
            insecure_root_capabilities=True,
            use_entrypoint=True,
            expand=True,
        )
        return self.container_.directory("$MELANGE_OUTPUT_DIR", expand=True).with_file(
            "melange.rsa.pub", self.public_key_, permissions=644
        )

    @function
    def with_build(
        self,
        config: Annotated[dagger.File, Doc("Config file")],
        signing_key: Annotated[dagger.File, Doc("Key to use for signing")]
        | None = None,
        arch: Annotated[str, Doc("Architectures to build for")] | None = None,
    ) -> Self:
        """Build a package from a YAML configuration file (for chaining)"""
        self.build(config=config, signing_key=signing_key, arch=arch)
        return self
