"""Interactive TUI for the techdebtfixer credential vault.

Two-pane layout: a client/project/secret tree on the left, a detail pane on
the right. The vault stays encrypted at rest (AES-256-GCM) and unlocks in
memory only after the master password is entered.

Run with: techdebtfixer --tui  (or python -m techdebtfixer.tui)
"""

from __future__ import annotations

from typing import Any, Callable

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Footer, Header, Input, Label, Static, Tree

from techdebtfixer.credentials import mask_secret
from techdebtfixer.vault import (
    Vault,
    VaultError,
    rotation_report,
    rotation_status,
)


class FormModal(ModalScreen[dict[str, str] | None]):
    """A small modal form with one or more fields."""

    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(
        self,
        title: str,
        fields: list[dict[str, Any]],
        on_submit: Callable[[dict[str, str]], None],
    ) -> None:
        super().__init__()
        self._title = title
        self._fields = fields
        self._on_submit = on_submit

    def compose(self) -> ComposeResult:
        yield Vertical(
            Label(self._title, classes="modal-title"),
            *[
                Input(
                    password=f.get("password", False),
                    placeholder=f.get("placeholder", ""),
                    value=f.get("default", ""),
                    id=f"field-{f['name']}",
                )
                for f in self._fields
            ],
            Horizontal(
                Button("Save", variant="primary", id="save-btn"),
                Button("Cancel", id="cancel-btn"),
                classes="modal-buttons",
            ),
            classes="modal-box",
        )

    def on_mount(self) -> None:
        inputs = self.query(Input)
        if inputs:
            inputs.first().focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "save-btn":
            self._submit()
        else:
            self.dismiss(None)

    def on_input_submitted(self) -> None:
        self._submit()

    def _submit(self) -> None:
        values: dict[str, str] = {}
        for f in self._fields:
            values[f["name"]] = self.query_one(f"#field-{f['name']}", Input).value
        self.dismiss(values)
        self._on_submit(values)


class ConfirmModal(ModalScreen[bool]):
    """Yes/no confirmation."""

    BINDINGS = [
        Binding("escape", "no", "No"),
        Binding("y", "yes", "Yes"),
        Binding("n", "no", "No"),
    ]

    def __init__(self, question: str) -> None:
        super().__init__()
        self._question = question

    def compose(self) -> ComposeResult:
        yield Vertical(
            Label(self._question, classes="modal-title"),
            Horizontal(
                Button("Yes", variant="error", id="yes-btn"),
                Button("No", id="no-btn"),
                classes="modal-buttons",
            ),
            classes="modal-box",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "yes-btn")

    def action_yes(self) -> None:
        self.dismiss(True)

    def action_no(self) -> None:
        self.dismiss(False)


class UnlockScreen(ModalScreen[None]):
    """Master-password entry; doubles as first-run vault creation."""

    BINDINGS = [Binding("escape", "quit_app", "Quit")]

    def __init__(self, creating: bool) -> None:
        super().__init__()
        self._creating = creating

    def compose(self) -> ComposeResult:
        fields: list[Any] = [
            Input(password=True, placeholder="master password", id="pw1"),
        ]
        if self._creating:
            fields.append(Input(password=True, placeholder="repeat password", id="pw2"))
        yield Vertical(
            Label(
                "Create a new vault - choose a master password"
                if self._creating
                else "Vault locked - enter master password",
                classes="modal-title",
            ),
            *fields,
            Horizontal(
                Button("Create vault" if self._creating else "Unlock",
                       variant="primary", id="go-btn"),
                classes="modal-buttons",
            ),
            classes="modal-box",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "go-btn":
            self._go()

    def on_input_submitted(self) -> None:
        self._go()

    def _go(self) -> None:
        app: "VaultTui" = self.app  # type: ignore[assignment]
        pw = self.query_one("#pw1", Input).value
        if not pw:
            app.notify("password must not be empty", severity="warning")
            return
        if self._creating:
            pw2 = self.query_one("#pw2", Input).value
            if pw != pw2:
                app.notify("passwords do not match", severity="error")
                return
            app.vault.create(pw)
            app.on_vault_ready(created=True)
        else:
            try:
                app.vault.unlock(pw)
            except VaultError as exc:
                app.notify(str(exc), severity="error")
                return
            app.on_vault_ready(created=False)
        self.dismiss(None)

    def action_quit_app(self) -> None:
        self.app.exit()


class VaultTui(App[None]):
    """Main two-pane vault manager."""

    TITLE = "techdebtfixer vault"
    CSS = """
    #main { height: 1fr; }
    #tree-pane { width: 48; min-width: 32; border-right: solid $accent;
                 padding: 0 1; }
    #detail-pane { padding: 0 2; }
    .modal-box { width: 60; margin: 1 2; padding: 1 2; border: solid $accent;
                 background: $surface; }
    .modal-title { margin-bottom: 1; text-style: bold; }
    .modal-buttons { height: auto; margin-top: 1; }
    .modal-buttons Button { margin-right: 1; }
    .detail-title { text-style: bold; margin-bottom: 1; }
    .detail-line { margin-bottom: 0; }
    .detail-gap { height: 1; }
    .hint { color: $text-muted; margin-top: 1; }
    Tree { background: $surface; }
    """

    BINDINGS = [
        Binding("n", "new_client", "New client"),
        Binding("p", "new_project", "New project"),
        Binding("s", "new_secret", "New secret"),
        Binding("c", "copy_secret", "Copy"),
        Binding("v", "toggle_reveal", "Reveal"),
        Binding("e", "edit_secret", "Edit"),
        Binding("r", "mark_rotated", "Rotated"),
        Binding("d", "delete", "Delete"),
        Binding("l", "lock", "Lock vault"),
        Binding("?", "help", "Help"),
        Binding("q", "quit", "Quit", key_display="q"),
    ]

    def __init__(self, vault: Vault) -> None:
        super().__init__()
        self.vault = vault
        self._revealed: set[str] = set()
        self._detail: Static | None = None

    # --- layout ------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="main"):
            yield Vertical(Tree("vault", id="client-tree"), id="tree-pane")
            yield Vertical(Static("", id="detail"), id="detail-pane")
        yield Footer()

    def on_mount(self) -> None:
        self._detail = self.query_one("#detail", Static)
        creating = not self.vault.exists
        self.push_screen(UnlockScreen(creating))
        self._refresh_detail()

    def on_vault_ready(self, created: bool) -> None:
        if created:
            self.notify(f"vault created at {self.vault.path}")
        else:
            self.notify("vault unlocked")
        self._rebuild_tree()

    # --- tree ---------------------------------------------------------

    def _rebuild_tree(self) -> None:
        tree = self.query_one("#client-tree", Tree)
        tree.clear()
        if not self.vault.unlocked:
            return
        data = self.vault.data
        root = tree.root
        root.label = "vault"
        root.data = {"kind": "root"}

        def mark(entry: "object") -> str:
            status = rotation_status(entry)  # type: ignore[arg-type]
            # Plain glyphs: tree labels go through Rich markup parsing, so
            # bracketed markers would be stripped as style tags.
            return {"overdue": " ⚠ overdue", "due-soon": " ⏳ due soon"}.get(
                status, ""
            )

        unfiled = data.secrets
        if unfiled:
            node = root.add(f"unfiled ({len(unfiled)})", data={"kind": "unfiled"})
            for entry in sorted(unfiled.values(), key=lambda s: s.name.lower()):
                node.add_leaf(
                    f"{entry.name}{mark(entry)}", data={
                        "kind": "secret", "client_id": "", "project_id": None,
                        "secret_id": entry.id,
                    },
                )
            node.expand()

        for client in sorted(data.clients.values(), key=lambda c: c.name.lower()):
            cnode = root.add(
                client.name,
                data={"kind": "client", "client_id": client.id},
            )
            for entry in sorted(client.secrets.values(), key=lambda s: s.name.lower()):
                cnode.add_leaf(
                    f"{entry.name}{mark(entry)}",
                    data={"kind": "secret", "client_id": client.id,
                          "project_id": None, "secret_id": entry.id},
                )
            for project in sorted(client.projects.values(),
                                  key=lambda p: p.name.lower()):
                pnode = cnode.add(
                    project.name,
                    data={"kind": "project",
                          "client_id": client.id, "project_id": project.id},
                )
                for entry in sorted(project.secrets.values(),
                                    key=lambda s: s.name.lower()):
                    pnode.add_leaf(
                        f"{entry.name}{mark(entry)}",
                        data={"kind": "secret", "client_id": client.id,
                              "project_id": project.id, "secret_id": entry.id},
                    )
            cnode.expand()
        root.expand()

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        self._refresh_detail(event.node.data)

    # --- detail pane ----------------------------------------------------

    def _selected(self) -> dict[str, Any] | None:
        tree = self.query_one("#client-tree", Tree)
        node = tree.cursor_node
        return node.data if node is not None else None

    def _refresh_detail(self, data: dict[str, Any] | None = None) -> None:
        if self._detail is None:
            return
        if data is None:
            data = self._selected()
        if not self.vault.unlocked or data is None:
            self._detail.update(
                "[b]techdebtfixer vault[/b]\n\n"
                "Locked. Unlock with the master password.\n\n"
                "Keys: n new client · p new project · s new secret · "
                "c copy · v reveal · d delete · l lock · q quit"
            )
            return
        kind = data.get("kind")
        if kind == "root":
            self._render_root_detail()
        elif kind == "unfiled":
            count = len(self.vault.data.secrets)
            self._detail.update(
                "[b]Unfiled secrets[/b]\n\n"
                f"{count} secret(s) not attached to any client.\n"
                "Select a secret to view or copy it."
            )
        elif kind == "client":
            self._render_client_detail(data["client_id"])
        elif kind == "project":
            self._render_project_detail(data["client_id"], data["project_id"])
        elif kind == "secret":
            self._render_secret_detail(
                data.get("client_id", ""), data.get("project_id"),
                data["secret_id"],
            )
        else:
            self._detail.update("(unknown selection)")

    def _render_root_detail(self) -> None:
        data = self.vault.data
        n_clients = len(data.clients)
        n_projects = sum(len(c.projects) for c in data.clients.values())
        n_secrets = len(data.secrets) + sum(
            len(c.secrets) + sum(len(p.secrets) for p in c.projects.values())
            for c in data.clients.values()
        )
        report = rotation_report(data)
        lines = [
            "[b]techdebtfixer vault[/b]",
            "",
            f"clients  : {n_clients}",
            f"projects : {n_projects}",
            f"secrets  : {n_secrets}",
        ]
        if report["overdue"] or report["due-soon"] or report["never"]:
            lines += [
                "",
                f"[red]rotation overdue : {len(report['overdue'])}[/red]",
                f"[yellow]due soon          : {len(report['due-soon'])}[/yellow]",
                f"[yellow]never rotated     : {len(report['never'])}[/yellow]",
            ]
        lines += [
            "",
            f"file     : {self.vault.path}",
            "",
            "n new client · p new project · s new secret",
        ]
        self._detail.update("\n".join(lines))

    def _render_client_detail(self, client_id: str) -> None:
        try:
            client = self.vault.get_client(client_id)
        except VaultError as exc:
            self._detail.update(f"[b]error[/b] {exc}")
            return
        lines = [
            f"[b]{client.name}[/b]",
            "",
            f"id        : {client.id}",
            f"projects  : {len(client.projects)}",
            f"secrets   : {len(client.secrets)} (client level)",
            f"created   : {client.created_at}",
            "",
            "p new project · s new client secret · d delete client",
        ]
        self._detail.update("\n".join(lines))

    def _render_project_detail(self, client_id: str, project_id: str) -> None:
        try:
            project = self.vault.get_project(client_id, project_id)
        except VaultError as exc:
            self._detail.update(f"[b]error[/b] {exc}")
            return
        lines = [
            f"[b]{project.name}[/b]",
            "",
            f"id        : {project.id}",
            f"secrets   : {len(project.secrets)}",
            f"created   : {project.created_at}",
            "",
            "s new project secret · d delete project",
        ]
        self._detail.update("\n".join(lines))

    def _render_secret_detail(
        self, client_id: str, project_id: str | None, secret_id: str
    ) -> None:
        try:
            entry = self.vault.get_secret(client_id, project_id, secret_id)
        except VaultError as exc:
            self._detail.update(f"[b]error[/b] {exc}")
            return
        value = entry.secret.decode("utf-8", errors="replace")
        revealed = secret_id in self._revealed
        shown = value if revealed else mask_secret(value)
        status = rotation_status(entry)
        status_text = {
            "overdue": "[red]rotation OVERDUE[/red]",
            "due-soon": "[yellow]rotation due soon[/yellow]",
            "never": "[yellow]never rotated (policy set)[/yellow]",
            "ok": "rotation ok",
            "off": "no rotation policy",
        }[status]
        rotate_line = (
            f"every {entry.rotate_days}d - {status_text}"
            if entry.rotate_days > 0
            else status_text
        )
        lines = [
            f"[b]{entry.name}[/b]",
            "",
            f"kind      : {entry.kind}",
            f"username  : {entry.username or '-'}",
            f"secret    : {shown}",
            f"rotation  : {rotate_line}",
            f"updated   : {entry.updated_at}",
        ]
        if entry.notes:
            lines += ["", f"notes     : {entry.notes}"]
        lines += ["", "c copy · v reveal/hide · e edit · r mark rotated · d delete"]
        self._detail.update("\n".join(lines))

    # --- helpers --------------------------------------------------------

    def _current_secret(self) -> tuple[str, str | None, str] | None:
        data = self._selected()
        if not data or data.get("kind") != "secret":
            self.notify("select a secret first", severity="warning")
            return None
        return data.get("client_id", ""), data.get("project_id"), data["secret_id"]

    # --- actions ---------------------------------------------------------

    def action_new_client(self) -> None:
        if not self._require_unlocked():
            return

        def submit(values: dict[str, str]) -> None:
            try:
                client = self.vault.add_client(values.get("name", ""))
            except VaultError as exc:
                self.notify(str(exc), severity="error")
                return
            self._rebuild_tree()
            self.notify(f"client '{client.name}' added")

        self.push_screen(
            FormModal("New client", [{"name": "name", "placeholder": "client name"}],
                      submit),
        )

    def action_new_project(self) -> None:
        if not self._require_unlocked():
            return
        data = self._selected()
        client_id = ""
        if data and data.get("kind") in ("client", "project", "secret"):
            client_id = data.get("client_id", "")
        if not client_id:
            self.notify("select a client first", severity="warning")
            return

        def submit(values: dict[str, str]) -> None:
            try:
                project = self.vault.add_project(client_id, values.get("name", ""))
            except VaultError as exc:
                self.notify(str(exc), severity="error")
                return
            self._rebuild_tree()
            self.notify(f"project '{project.name}' added")

        self.push_screen(
            FormModal("New project",
                      [{"name": "name", "placeholder": "project name"}], submit),
        )

    def action_new_secret(self) -> None:
        if not self._require_unlocked():
            return
        data = self._selected() or {}
        kind = data.get("kind", "root")
        client_id = data.get("client_id", "") if data else ""
        project_id = data.get("project_id") if data else None
        if kind == "unfiled":
            client_id, project_id = "", None
        elif kind == "client":
            project_id = None
        elif kind != "root":
            self.notify("select a client, project or unfiled node first",
                        severity="warning")
            return

        fields = [
            {"name": "name", "placeholder": "secret name (e.g. staging API key)"},
            {"name": "kind", "placeholder": "kind (api-key, password, token…)",
             "default": "api-key"},
            {"name": "username", "placeholder": "username (optional)"},
            {"name": "secret", "placeholder": "secret value", "password": True},
            {"name": "rotate_days", "placeholder": f"rotate every N days (0 = off)",
             "default": "0"},
            {"name": "notes", "placeholder": "notes (optional)"},
        ]

        def submit(values: dict[str, str]) -> None:
            try:
                entry = self.vault.add_secret(
                    client_id, project_id,
                    name=values.get("name", ""),
                    kind=values.get("kind", "api-key"),
                    username=values.get("username", ""),
                    secret=values.get("secret", ""),
                    notes=values.get("notes", ""),
                    rotate_days=_to_int(values.get("rotate_days")),
                )
            except VaultError as exc:
                self.notify(str(exc), severity="error")
                return
            self._rebuild_tree()
            self.notify(f"secret '{entry.name}' stored encrypted")

        self.push_screen(FormModal("New secret", fields, submit))

    def action_copy_secret(self) -> None:
        target = self._current_secret()
        if target is None:
            return
        client_id, project_id, secret_id = target
        try:
            entry = self.vault.get_secret(client_id, project_id, secret_id)
        except VaultError as exc:
            self.notify(str(exc), severity="error")
            return
        self.copy_to_clipboard(entry.secret.decode("utf-8", errors="replace"))
        self.notify(f"copied '{entry.name}' to clipboard")

    def action_toggle_reveal(self) -> None:
        target = self._current_secret()
        if target is None:
            return
        _, _, secret_id = target
        if secret_id in self._revealed:
            self._revealed.discard(secret_id)
        else:
            self._revealed.add(secret_id)
        self._refresh_detail()

    def action_mark_rotated(self) -> None:
        target = self._current_secret()
        if target is None:
            return
        client_id, project_id, secret_id = target
        try:
            entry = self.vault.mark_rotated(client_id, project_id, secret_id)
        except VaultError as exc:
            self.notify(str(exc), severity="error")
            return
        self._rebuild_tree()
        self._refresh_detail()
        self.notify(f"'{entry.name}' marked as rotated today")

    def action_edit_secret(self) -> None:
        target = self._current_secret()
        if target is None:
            return
        client_id, project_id, secret_id = target
        try:
            entry = self.vault.get_secret(client_id, project_id, secret_id)
        except VaultError as exc:
            self.notify(str(exc), severity="error")
            return
        fields = [
            {"name": "name", "default": entry.name},
            {"name": "kind", "default": entry.kind},
            {"name": "username", "default": entry.username},
            {"name": "secret", "password": True,
             "placeholder": "new value (leave blank to keep)"},
            {"name": "rotate_days", "default": str(entry.rotate_days),
             "placeholder": "rotate every N days (0 = off)"},
            {"name": "notes", "default": entry.notes},
        ]

        def submit(values: dict[str, str]) -> None:
            try:
                self.vault.update_secret(
                    client_id, project_id, secret_id,
                    name=values.get("name"),
                    kind=values.get("kind"),
                    username=values.get("username"),
                    secret=values.get("secret") or None,
                    notes=values.get("notes"),
                    rotate_days=_to_int(values.get("rotate_days")),
                )
            except VaultError as exc:
                self.notify(str(exc), severity="error")
                return
            self._rebuild_tree()
            self.notify("secret updated")

        self.push_screen(FormModal(f"Edit '{entry.name}'", fields, submit))

    def action_delete(self) -> None:
        if not self._require_unlocked():
            return
        data = self._selected()
        if not data:
            self.notify("nothing selected", severity="warning")
            return
        kind = data.get("kind")

        if kind == "secret":
            client_id, project_id, secret_id = (
                data.get("client_id", ""), data.get("project_id"),
                data["secret_id"],
            )
            try:
                entry = self.vault.get_secret(client_id, project_id, secret_id)
            except VaultError as exc:
                self.notify(str(exc), severity="error")
                return

            def confirmed(delete: bool | None) -> None:
                if delete:
                    self.vault.delete_secret(client_id, project_id, secret_id)
                    self._rebuild_tree()
                    self.notify(f"deleted secret '{entry.name}'")

            self.push_screen(
                ConfirmModal(f"Delete secret '{entry.name}'?"), confirmed
            )
        elif kind == "client":
            try:
                client = self.vault.get_client(data["client_id"])
            except VaultError as exc:
                self.notify(str(exc), severity="error")
                return

            def confirmed(delete: bool | None) -> None:
                if delete:
                    self.vault.delete_client(client.id)
                    self._rebuild_tree()
                    self.notify(f"deleted client '{client.name}'")

            self.push_screen(
                ConfirmModal(
                    f"Delete client '{client.name}' and ALL its projects and "
                    "secrets?"
                ),
                confirmed,
            )
        elif kind == "project":
            try:
                project = self.vault.get_project(
                    data["client_id"], data["project_id"]
                )
            except VaultError as exc:
                self.notify(str(exc), severity="error")
                return

            def confirmed(delete: bool | None) -> None:
                if delete:
                    self.vault.delete_project(data["client_id"], project.id)
                    self._rebuild_tree()
                    self.notify(f"deleted project '{project.name}'")

            self.push_screen(
                ConfirmModal(f"Delete project '{project.name}' and its secrets?"),
                confirmed,
            )
        else:
            self.notify("select a client, project or secret to delete",
                        severity="warning")

    def action_lock(self) -> None:
        self.vault.lock()
        self._revealed.clear()
        self._rebuild_tree()
        self._refresh_detail()
        self.push_screen(UnlockScreen(False))
        self.notify("vault locked")

    def action_help(self) -> None:
        self.notify(
            "n client · p project · s secret · c copy · v reveal · "
            "e edit · r mark rotated · d delete · l lock"
        )

    def action_quit(self) -> None:
        self.vault.lock()
        self.exit()

    def _require_unlocked(self) -> bool:
        if not self.vault.unlocked:
            self.notify("vault is locked", severity="warning")
            return False
        return True


def _to_int(value: str | None) -> int:
    """Parse a form field as int, defaulting to 0 on blank or garbage."""
    try:
        return max(0, int((value or "").strip()))
    except ValueError:
        return 0


def run(vault_path: str | None = None) -> int:
    """Entry point for `techdebtfixer --tui` and `python -m techdebtfixer.tui`."""
    app = VaultTui(Vault(vault_path))
    app.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
