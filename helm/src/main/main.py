from typing import Annotated, Self
from urllib.parse import urlparse

import dagger
from dagger import Doc, Name, dag, function, field, object_type


@object_type
class Helm:
    """Helm module"""

    image: Annotated[str, Doc("Helm image")] = field(
        default="cgr.dev/chainguard/wolfi-base:latest"
    )
    version: Annotated[str, Doc("Helm version")] | None = field(default=None)
    user: Annotated[str, Doc("image user")] | None = field(default="65532")

    container_: dagger.Container | None = None

    @function
    def container(self) -> dagger.Container:
        """Returns container"""
        if self.container_:
            return self.container_

        container: dagger.Container = dag.container()
        pkg = "helm"
        if self.version:
            pkg = f"{pkg}~{self.version}"

        self.container_ = (
            container.from_(address=self.image)
            .with_user("0")
            .with_exec(["apk", "add", "--no-cache", "kubectl", pkg])
            .with_entrypoint(["/usr/bin/helm"])
            .with_user(self.user)
        )

        return self.container_

    @function
    def with_registry_auth(
        self,
        username: Annotated[str, Doc("Registry username")],
        secret: Annotated[dagger.Secret, Doc("Registry password")],
        address: Annotated[str, Doc("Registry host")] | None = "docker.io",
    ) -> Self:
        """Authenticate with registry"""
        container: dagger.Container = self.container()
        cmd = [
            "sh",
            "-c",
            (
                f"helm registry login {address}"
                f" --username {username}"
                " --password ${REGISTRY_PASSWORD}"
            ),
        ]
        self.container_ = container.with_secret_variable(
            "REGISTRY_PASSWORD", secret
        ).with_exec(cmd, use_entrypoint=False)
        return self

    def get_registry_host(self, address: str) -> str:
        """Retrieves the registry host from the given address"""
        url = None
        if address.startswith("oci://"):
            url = urlparse(address)
        else:
            url = urlparse(f"//{address}")
        return url.netloc

    @function
    async def lint(
        self,
        path: Annotated[dagger.Directory, Doc("Path to the chart")],
        strict: Annotated[bool, Doc("Fail on lint warnings")] | None = False,
        quiet: Annotated[bool, Doc("Print only warnings and errors")] | None = False,
    ) -> str:
        """Verify that the chart is well-formed"""
        container: dagger.Container = (
            self.container()
            .with_env_variable("HELM_CHART_PATH", "/tmp/chart")
            .with_directory("$HELM_CHART_PATH", path, expand=True)
            .with_workdir("$HELM_CHART_PATH", expand=True)
        )

        cmd = ["lint", "."]
        if strict:
            cmd.extend(["--strict"])
        if quiet:
            cmd.extend(["--quiet"])

        return await container.with_exec(cmd, use_entrypoint=True).stdout()

    @function
    async def with_lint(
        self,
        path: Annotated[dagger.Directory, Doc("Path to the chart")],
        strict: Annotated[bool, Doc("Fail on lint warnings")] | None = False,
        quiet: Annotated[bool, Doc("Print only warnings and errors")] | None = False,
    ) -> Self:
        """Verify that the chart is well-formed (for chaining)"""
        await self.lint(path=path, strict=strict, quiet=quiet)
        return self

    @function
    async def template(
        self,
        path: Annotated[dagger.Directory, Doc("Path to the chart")],
        show_only: Annotated[
            list[str], Doc("Only show manifests rendered from the given templates")
        ]
        | None = None,
        sets: Annotated[list[str], Doc("Set values on the command"), Name("set")]
        | None = None,
        set_files: Annotated[
            list[str],
            Doc("Set values from respective files specified via the command"),
            Name("set_file"),
        ]
        | None = None,
        set_jsons: Annotated[
            list[dagger.File], Doc("Set JSON values on the command"), Name("set_json")
        ]
        | None = None,
        set_literals: Annotated[
            list[dagger.File],
            Doc("Set a literal STRING value on the command"),
            Name("set_literal"),
        ]
        | None = None,
        set_strings: Annotated[
            list[dagger.File],
            Doc("Set STRING values on the command line"),
            Name("set_string"),
        ]
        | None = None,
    ) -> str:
        """Render chart templates locally and display the output"""
        container: dagger.Container = (
            self.container()
            .with_env_variable("HELM_CHART_PATH", "/tmp/chart")
            .with_directory("$HELM_CHART_PATH", path, expand=True)
            .with_workdir("$HELM_CHART_PATH", expand=True)
        )

        cmd = ["template", "."]
        if show_only:
            cmd.extend(["--set", ",".join(show_only)])
        if sets:
            cmd.extend(["--set", ",".join(sets)])
        if set_files:
            cmd.extend(["--set-file", ",".join(set_files)])
        if set_jsons:
            cmd.extend(["--set-json", ",".join(set_jsons)])
        if set_literals:
            cmd.extend(["--set-literal", ",".join(set_literals)])
        if set_strings:
            cmd.extend(["--set-string", ",".join(set_strings)])

        return await container.with_exec(cmd, use_entrypoint=True).stdout()

    @function
    async def package(
        self,
        path: Annotated[dagger.Directory, Doc("Path to the chart")],
        app_version: Annotated[
            str, Doc("Set the appVersion on the chart to this version")
        ]
        | None = None,
        version: Annotated[
            str, Doc("Set the version on the chart to this semver version")
        ]
        | None = None,
        dependency_update: Annotated[bool, Doc("Update dependencies")] | None = False,
    ) -> dagger.File:
        """Packages a chart into a versioned chart archive file"""
        container: dagger.Container = (
            self.container()
            .with_env_variable("HELM_CHART_PATH", "/tmp/chart")
            .with_env_variable("HELM_CHART_DEST_PATH", "/tmp/dest")
            .with_directory("$HELM_CHART_PATH", path, owner=self.user, expand=True)
            .with_workdir("$HELM_CHART_PATH", expand=True)
        )

        cmd = ["package", ".", "--destination", "$HELM_CHART_DEST_PATH"]
        if app_version:
            cmd.extend(["--app-version", app_version])
        if version:
            cmd.extend(["--version", version])
        if dependency_update:
            cmd.extend(["--dependency-update"])

        dest_dir: dagger.Directory = await container.with_exec(
            cmd, use_entrypoint=True, expand=True
        ).directory("$HELM_CHART_DEST_PATH", expand=True)
        dest_files: list[str] = await dest_dir.glob("*.tgz")

        return dest_dir.file(dest_files[0])

    @function
    async def push(
        self,
        chart: Annotated[dagger.File, Doc("Path to the chart")],
        registry: Annotated[str, Doc("Registry host")],
        username: Annotated[str, Doc("Registry username")] | None = None,
        password: Annotated[dagger.Secret, Doc("Registry password")] | None = None,
        plain_http: Annotated[
            bool, Doc("Use insecure HTTP connections for the chart upload")
        ]
        | None = False,
    ) -> str:
        """Verify that the chart is well-formed"""
        if username and password:
            self.with_registry_auth(
                username=username,
                secret=password,
                address=self.get_registry_host(registry),
            )

        container: dagger.Container = (
            self.container()
            .with_env_variable("HELM_CHART", "/tmp/chart.tgz")
            .with_file("$HELM_CHART", chart, owner=self.user, expand=True)
        )

        oci_registry: str = None
        if registry.startswith("oci://"):
            oci_registry = registry
        else:
            oci_registry = f"oci://{registry}"

        cmd = ["push", "$HELM_CHART", oci_registry]
        if plain_http:
            cmd.extend(["--plain-http"])

        return await container.with_exec(cmd, use_entrypoint=True, expand=True).stdout()

    @function
    async def package_push(
        self,
        path: Annotated[dagger.Directory, Doc("Path to the chart")],
        registry: Annotated[str, Doc("Registry host")],
        username: Annotated[str, Doc("Registry username")] | None = None,
        password: Annotated[dagger.Secret, Doc("Registry password")] | None = None,
        plain_http: Annotated[
            bool, Doc("Use insecure HTTP connections for the chart upload")
        ]
        | None = False,
        app_version: Annotated[
            str, Doc("Set the appVersion on the chart to this version")
        ]
        | None = None,
        version: Annotated[
            str, Doc("Set the version on the chart to this semver version")
        ]
        | None = None,
        dependency_update: Annotated[bool, Doc("Update dependencies")] | None = False,
    ) -> str:
        """Packages a chart an push it to the registry"""

        chart: dagger.File = await self.package(
            path=path,
            app_version=app_version,
            version=version,
            dependency_update=dependency_update,
        )

        return await self.push(
            chart=chart,
            registry=registry,
            username=username,
            password=password,
            plain_http=plain_http,
        )
