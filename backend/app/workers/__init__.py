"""Reserved for application-wide background workers; none exist yet.

The network module owns its worker threads (``app.network``): the capture consumer, the PCAP
analysis thread and the enrichment worker.
"""
