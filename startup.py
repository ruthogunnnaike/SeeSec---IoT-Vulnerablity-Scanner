

def launch():
    def launch():
        from pox.log.level import launch
        launch(DEBUG=True)

        from pox.misc.firewall import launch
        launch()

        from pox.openflow.keepalive import launch
        launch(interval=300)

        from pox.forwarding.l3_learning import launch
        launch()

        from pox.proto.dhcpd import launch
        launch()

        from pox.proto.dns_spy import launch
        launch()

        from pox.host_tracker.host_tracker import launch
        launch()

        from pox.openflow.discovery import launch
        launch()  # 15 seconds

        from pox.forwarding.l2_pairs import launch
        launch()

