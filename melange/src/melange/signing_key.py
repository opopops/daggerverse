from typing import Annotated, Self

import dagger
from dagger import Doc, dag, field, function, object_type


@object_type
class SigningKey:
    """Signing Key"""

    name: str | None = field(default="melange.rsa")
    private: dagger.Secret | None = field(default=None)

    container: dagger.Container
    user: str

    @function
    def generate(
        self,
        name: Annotated[str | None, Doc("Key name")] = "melange.rsa",
        size: Annotated[int | None, Doc("the size of the prime to calculate ")] = 4096,
    ) -> dagger.Directory:
        """Generate a key pair for package signing"""
        cmd = ["keygen", "--key-size", str(size), name]
        return self.container.with_exec(
            cmd, use_entrypoint=True, expand=True
        ).directory(".")

    @function
    async def with_generate(
        self,
        name: Annotated[str | None, Doc("Key name")] = "melange.rsa",
        size: Annotated[int | None, Doc("the size of the prime to calculate ")] = 4096,
    ) -> Self:
        """Generate a key pair for package signing for chaining (for testing purpose)"""
        keys_dir: dagger.Directory = self.generate(name=name, size=size)
        self.name = name
        self.private = dag.set_secret(name, await keys_dir.file(name).contents())
        return self

    @function
    def public(self) -> dagger.File:
        """Return the public key"""
        return (
            self.container.with_mounted_secret(
                "/tmp/melange.rsa",
                source=self.private,
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
