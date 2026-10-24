"""One missing slash handler must not take down every inbound message (#143844)."""
from gateway.run_busy import GatewayBusySessionMixin


def test_missing_handler_is_omitted_and_logged_once():
    class Host(GatewayBusySessionMixin):
        def _handle_status_command(self, _event):
            return "ok"

    GatewayBusySessionMixin._missing_command_handlers.clear()
    host = Host()
    assert set(host._command_handler_table(("status", "autoprune"))) == {"status"}
    assert set(host._command_handler_table(("status", "autoprune"))) == {"status"}
    assert GatewayBusySessionMixin._missing_command_handlers == {"_handle_autoprune_command"}


def test_idle_dispatch_table_builds_when_a_listed_command_has_no_method():
    GatewayBusySessionMixin._missing_command_handlers.clear()
    host = GatewayBusySessionMixin()
    assert host._gateway_plain_command_handlers().get(None) is None
    assert "_handle_autoprune_command" in GatewayBusySessionMixin._missing_command_handlers
