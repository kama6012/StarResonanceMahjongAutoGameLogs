import unittest
import io
import json
import tempfile
from pathlib import Path

from protocol.frames import StreamDecoder
from protocol.mahjong_state import snapshot_from_decoded, snapshot_from_world_update


def _varint(value):
    result = bytearray()
    while value >= 0x80:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value)
    return bytes(result)


def _field(number, value, wire=0):
    key = _varint((number << 3) | wire)
    return key + (_varint(value) if wire == 0 else _varint(len(value)) + value)


def _world_update(dora=52, current=1, self_index=2, public_melds=None,
                  public_meld_types=None, private_meld_type=1,
                  riichi_sticks=0, honba=0, seat_winds=(0, 1, 2, 3)):
    public_melds = public_melds or {}
    public_meld_types = public_meld_types or {}
    players = []
    for index, discards in enumerate(([112, 130], [86], [], [105])):
        player = _field(2, index) + _field(4, seat_winds[index]) + _field(6, b"".join(_varint(tile) for tile in discards), 2)
        for meld_index, cards in enumerate(public_melds.get(index, ())):
            meld_type = public_meld_types.get(index, ())[meld_index] if meld_index < len(public_meld_types.get(index, ())) else 0
            meld_data = (b"" if meld_type == 0 else _field(1, meld_type))
            meld_data += _field(2, b"".join(_varint(tile) for tile in cards), 2)
            player += _field(7, meld_data, 2)
        players.append(_field(7, player, 2))
    hand = _field(10, b"".join(_varint(tile) for tile in range(13)), 2)
    meld = _field(1, private_meld_type) + _field(2, b"".join(_varint(tile) for tile in (40, 41, 42)), 2)
    owner_index = b"" if self_index == 0 else _field(2, self_index)
    private = _field(1, owner_index + _field(7, meld, 2) + hand, 2)
    action = _field(1, 1) + _field(2, 3) + _field(3, 52) + _field(5, 17)
    counters = (b"" if riichi_sticks == 0 else _field(4, riichi_sticks))
    counters += (b"" if honba == 0 else _field(5, honba))
    table = _field(1, action, 2) + _field(2, _varint(dora), 2) + _field(3, current) + counters + b"".join(players) + _field(8, private, 2)
    return _field(1, _field(3, _field(3, table, 2), 2), 2)


class ProtocolTests(unittest.TestCase):
    def _snapshot(self, **changes):
        from protocol import TableSnapshot
        values = dict(
            discards=((), (), (), ()), dora_indicators=(52,),
            hand=tuple(range(13)), self_index=0,
            scores=(25000, 25000, 25000, 25000),
            card_counts=(13, 13, 13, 13), dealer_index=0, round_wind=0,
        )
        values.update(changes)
        return TableSnapshot(**values)

    def test_stream_decoder_does_not_spin_on_short_unknown_header(self):
        decoder = StreamDecoder()
        self.assertEqual(decoder.feed(b"\x00\x00\x00\x00\x00\x00"), [])

    def test_stream_decoder_handles_fragmentation(self):
        payload = b"\x00" * 4 + b"c3SB" + b"\x00" * 7 + b"\x09" + b"\x08\x01"
        inner = (6 + len(payload)).to_bytes(4, "big") + b"\x00\x02" + payload
        outer_body = b"\x00\x06\x00\x00\x00\x01" + inner
        record = (4 + len(outer_body)).to_bytes(4, "big") + outer_body
        decoder = StreamDecoder()
        self.assertEqual(decoder.feed(record[:7]), [])
        messages = decoder.feed(record[7:])
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0].command, 9)
        self.assertEqual(messages[0].protobuf, b"\x08\x01")

    def test_snapshot_requires_four_valid_players(self):
        data = {
            "Players": [{"PlayerIndex": i, "DropCards": [i, i + 4]} for i in range(4)],
            "Doras": [40],
            "CurrentIndex": 2,
        }
        snapshot = snapshot_from_decoded(data)
        self.assertIsNotNone(snapshot)
        self.assertEqual(snapshot.discards[2], (2, 6))
        self.assertEqual(snapshot.dora_indicators, (40,))

    def test_snapshot_rejects_false_positive_values(self):
        data = {
            "Players": [{"PlayerIndex": i, "DropCards": [i]} for i in range(4)],
            "Doras": [40810513024],
        }
        self.assertIsNone(snapshot_from_decoded(data))

    def test_world_update_extracts_packed_varint_tiles(self):
        snapshot = snapshot_from_world_update(_world_update())
        self.assertIsNotNone(snapshot)
        self.assertEqual(snapshot.discards, ((112, 130), (86,), (), (105,)))
        self.assertEqual(snapshot.dora_indicators, (52,))
        self.assertEqual(snapshot.current_player, 1)
        self.assertEqual(snapshot.player_melds, ((), (), (), ()))
        self.assertEqual(snapshot.player_meld_types, ((), (), (), ()))
        self.assertEqual(snapshot.hand, tuple(range(13)))
        self.assertEqual(snapshot.self_index, 2)
        self.assertEqual(snapshot.melds, ((40, 41, 42),))
        self.assertEqual(snapshot.meld_types, (1,))
        self.assertEqual(snapshot.last_discard_event, (3, 52, 17))

    def test_stream_decoder_handles_8002_zstd_snapshot(self):
        import zstandard as zstd

        protobuf = _world_update()
        sink = io.BytesIO()
        with zstd.ZstdCompressor().stream_writer(sink, closefd=False) as writer:
            writer.write(protobuf)
        payload = b"\x00" * 16 + sink.getvalue()
        body = b"\x80\x02\x00\x00\x00\x00" + payload
        record = (4 + len(body)).to_bytes(4, "big") + body
        messages = StreamDecoder().feed(record)
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0].outer_type, 0x8002)
        self.assertEqual(messages[0].protobuf, protobuf)
        self.assertIsNotNone(snapshot_from_world_update(messages[0].protobuf))

    def test_world_update_treats_omitted_owner_index_as_player_zero(self):
        snapshot = snapshot_from_world_update(_world_update(self_index=0))
        self.assertIsNotNone(snapshot)
        self.assertEqual(snapshot.self_index, 0)

    def test_world_update_extracts_public_melds_for_every_player(self):
        snapshot = snapshot_from_world_update(_world_update(
            public_melds={
                0: ((0, 1, 2),),
                1: ((80, 81, 82, 83),),
                3: ((68, 69, 71), (108, 110, 111)),
            },
            public_meld_types={0: (0,), 1: (3,), 3: (1, 4)},
        ))
        self.assertIsNotNone(snapshot)
        self.assertEqual(snapshot.player_melds[0], ((0, 1, 2),))
        self.assertEqual(snapshot.player_melds[1], ((80, 81, 82, 83),))
        self.assertEqual(snapshot.player_melds[2], ())
        self.assertEqual(snapshot.player_melds[3], ((68, 69, 71), (108, 110, 111)))
        self.assertEqual(snapshot.player_meld_types, ((0,), (3,), (), (1, 4)))

    def test_public_meld_renderer_separates_meld_groups(self):
        from realtime_pipeline import render_melds

        self.assertEqual(render_melds(((0, 4, 8), (108, 110, 111)), (0, 3)), "123m / 111Z")
        self.assertEqual(render_melds(()), "—")

    def test_compact_hand_uses_lowercase_closed_tiles_and_uppercase_melds(self):
        from realtime_pipeline import render_compact

        compact = render_compact((4, 8, 36, 72, 112), ((124, 125, 126, 127),), (3,))
        self.assertEqual(compact, "23m1p1s2z#5555Z")

    def test_open_kan_stays_lowercase(self):
        from realtime_pipeline import render_compact

        compact = render_compact((4, 8, 36, 72, 112), ((124, 125, 126, 127),), (4,))
        self.assertEqual(compact, "23m1p1s2z#5555z")

    def test_closed_kan_uppercases_suit_but_not_red_prefix(self):
        from realtime_pipeline import render_melds

        self.assertEqual(render_melds(((16, 17, 18, 19),), (3,)), "r5555M")

    def test_red_five_tile_names_are_visible_in_river(self):
        from analysis.tiles import tile_id_to_str

        self.assertEqual(tile_id_to_str(16), "5m")
        self.assertEqual(tile_id_to_str(52), "5p")
        self.assertEqual(tile_id_to_str(88), "5s")
        self.assertEqual(tile_id_to_str(19), "r5m")
        self.assertEqual(tile_id_to_str(55), "r5p")
        self.assertEqual(tile_id_to_str(91), "r5s")

    def test_packet_capture_can_skip_per_packet_file_writes(self):
        from packet_capture_bin import PacketCapture

        capture = PacketCapture(None, "", ".", write_files=False)
        self.assertFalse(capture.write_files)

    def test_tcp_payload_orderer_deduplicates_and_reorders(self):
        from realtime_pipeline import TcpPayloadOrderer

        orderer = TcpPayloadOrderer()
        self.assertEqual(orderer.feed(100, b"abc", now=0), b"abc")
        self.assertEqual(orderer.feed(106, b"ghi", now=0), b"")
        self.assertEqual(orderer.feed(103, b"def", now=0), b"defghi")
        self.assertEqual(orderer.feed(100, b"abcdef", now=0), b"")

    def test_tcp_payload_orderer_recovers_after_missing_gap(self):
        from realtime_pipeline import TcpPayloadOrderer

        orderer = TcpPayloadOrderer(gap_timeout=0.5)
        self.assertEqual(orderer.feed(10, b"aa", now=0), b"aa")
        self.assertEqual(orderer.feed(20, b"bb", now=0), b"")
        self.assertEqual(orderer.feed(22, b"cc", now=1), b"bbcc")

    def test_tracking_session_maps_full_table_state_and_deduplicates(self):
        from app.session import SessionCoordinator

        snapshot = self._snapshot(
            hand=(0, 4, 8, 19), self_index=2, dealer_index=1, current_player=2,
            round_wind=1, honba=2, riichi_sticks=1,
            scores=(24000, 26000, 25000, 25000), seat_winds=(3, 0, 1, 2),
            riichi_states=(0, 2, 1, 0),
            discards=((72,), (76,), (80,), (84,)),
            player_melds=((), ((40, 41, 42),), (), ()),
            player_meld_types=((), (1,), (), ()),
        )
        session = SessionCoordinator()
        view = session.accept(snapshot)
        self.assertEqual(view.round_label, "東2局")
        self.assertEqual(view.honba, 2)
        self.assertEqual(view.riichi_sticks, 1)
        self.assertEqual(view.dealer_label, "プレイヤー 2")
        self.assertEqual(view.current_label, "プレイヤー 3")
        self.assertIn("r5m", view.hand)
        self.assertEqual(view.players[1].melds, "222p")
        self.assertEqual(view.players[2].markers, "自分 / 手番 / 立直宣言")
        self.assertEqual(view.players[1].markers, "親 / 立直成立")
        self.assertIsNone(session.accept(snapshot))

    def test_tracking_session_preserves_river_order(self):
        from app.session import SessionCoordinator

        view = SessionCoordinator().accept(
            self._snapshot(discards=((72, 108, 76), (), (), ()))
        )
        self.assertEqual(view.players[0].river, "1s 1z 2s")

    def test_world_update_defaults_omitted_dealer_to_player_zero(self):
        snapshot = snapshot_from_world_update(_world_update())
        self.assertIsNotNone(snapshot)
        self.assertEqual(snapshot.dealer_index, 0)

    def test_world_update_extracts_op_message_honba_and_riichi_sticks(self):
        snapshot = snapshot_from_world_update(
            _world_update(honba=2, riichi_sticks=1, seat_winds=(3, 0, 1, 2))
        )
        self.assertIsNotNone(snapshot)
        self.assertEqual(snapshot.dealer_index, 1)
        self.assertEqual(snapshot.honba, 2)
        self.assertEqual(snapshot.riichi_sticks, 1)

    def test_tracker_resets_omitted_counters_within_same_round(self):
        from protocol import MahjongStateTracker

        tracker = MahjongStateTracker()
        first = tracker.feed_protobuf(_world_update(honba=2, riichi_sticks=1))
        second = tracker.feed_protobuf(_world_update(current=2))
        self.assertEqual(first.honba, 2)
        self.assertEqual(first.riichi_sticks, 1)
        self.assertEqual(second.honba, 0)
        self.assertEqual(second.riichi_sticks, 0)

    def test_tracker_resets_omitted_counters_on_new_round(self):
        from protocol import MahjongStateTracker

        tracker = MahjongStateTracker()
        tracker.feed_protobuf(_world_update(honba=2, riichi_sticks=1))
        next_round = tracker.feed_protobuf(_world_update(seat_winds=(3, 0, 1, 2)))
        self.assertEqual(next_round.dealer_index, 1)
        self.assertEqual(next_round.honba, 0)
        self.assertEqual(next_round.riichi_sticks, 0)

    def test_tracking_session_always_displays_east_round(self):
        from app.session import SessionCoordinator

        view = SessionCoordinator().accept(self._snapshot(dealer_index=3, round_wind=2))
        self.assertEqual(view.round_label, "東4局")

    def test_tracking_session_infers_missing_dealer_from_east_seat(self):
        from app.session import SessionCoordinator

        view = SessionCoordinator().accept(
            self._snapshot(dealer_index=None, seat_winds=(2, 3, 0, 1))
        )
        self.assertEqual(view.dealer_label, "プレイヤー 3")
        self.assertEqual(view.round_label, "東3局")
        self.assertTrue(view.players[2].is_dealer)

    def test_tracking_session_keeps_last_dealer_when_update_omits_it(self):
        from app.session import SessionCoordinator

        session = SessionCoordinator()
        session.accept(self._snapshot(dealer_index=1))
        view = session.accept(
            self._snapshot(dealer_index=None, seat_winds=(9, 9, 9, 9), current_player=2)
        )
        self.assertEqual(view.dealer_label, "プレイヤー 2")

    def test_game_record_writes_structured_json_and_deduplicates(self):
        from app.game_record import GameRecordWriter

        with tempfile.TemporaryDirectory() as directory:
            writer = GameRecordWriter(Path(directory))
            snapshot = self._snapshot(
                discards=((72,), (), (), ()),
                player_melds=((), ((40, 41, 42),), (), ()),
                player_meld_types=((), (1,), (), ()),
            )
            path = writer.append(snapshot)
            writer.append(snapshot)
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(data["schema"], "star-resonance-mahjong-record")
            self.assertFalse(data["completed"])
            self.assertEqual(len(data["events"]), 1)
            self.assertEqual(data["events"][0]["round_wind"], "east")
            self.assertEqual(data["events"][0]["players"][0]["discards"], [72])
            self.assertEqual(data["events"][0]["players"][1]["melds"], [[40, 41, 42]])
            self.assertFalse(list(Path(directory).glob("*.tmp")))
            writer.close()
            completed = json.loads(path.read_text(encoding="utf-8"))
            self.assertTrue(completed["completed"])
            self.assertIn("ended_at", completed)

    def test_game_record_splits_when_a_new_pristine_game_starts(self):
        from app.game_record import GameRecordWriter

        with tempfile.TemporaryDirectory() as directory:
            writer = GameRecordWriter(Path(directory))
            writer.append(self._snapshot(
                scores=(26000, 24000, 25000, 25000),
                discards=((72,), (), (), ()),
            ))
            writer.append(self._snapshot())
            writer.close()
            paths = sorted(Path(directory).glob("game_*.json"))
            self.assertEqual(len(paths), 2)
            records = [json.loads(path.read_text(encoding="utf-8")) for path in paths]
            self.assertTrue(all(record["completed"] for record in records))
            self.assertEqual([len(record["events"]) for record in records], [1, 1])


if __name__ == "__main__":
    unittest.main()