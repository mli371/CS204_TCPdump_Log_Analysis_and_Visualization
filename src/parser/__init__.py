"""Parsers that translate packet captures or text into canonical events."""

from .pcap_reader import Event, parse_pcap

__all__ = ["Event", "parse_pcap"]
