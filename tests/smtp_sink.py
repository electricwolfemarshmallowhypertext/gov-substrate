"""Disposable real SMTP receiver. Never relays messages to a human mailbox."""

from aiosmtpd.controller import Controller


class LocalSMTPSink:
    def __init__(self):
        self.messages = []
        self.mail_commands = 0
        sink = self

        class Handler:
            async def handle_MAIL(self, server, session, envelope, address, options):
                sink.mail_commands += 1
                envelope.mail_from = address
                envelope.mail_options.extend(options)
                return "250 OK"

            async def handle_DATA(self, server, session, envelope):
                sink.messages.append({"sender": envelope.mail_from,
                                      "recipients": list(envelope.rcpt_tos),
                                      "data": bytes(envelope.original_content)})
                return "250 Accepted into disposable sink"

        class EphemeralController(Controller):
            def _trigger_server(self):
                self.port = self.server.sockets[0].getsockname()[1]
                super()._trigger_server()

        self.controller = EphemeralController(Handler(), hostname="127.0.0.1", port=0,
                                              data_size_limit=262144)
        self.controller.start()
        self.port = self.controller.port

    def close(self):
        self.controller.stop()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
