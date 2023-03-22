import file_finder.ux
import unittest


class HumanHelpers(unittest.TestCase):
    def test_get_human_readable_number_of_bytes_with_metric_system(self):
        for sz, expected in [
            [0, "0 Bytes"],
            [1, "1 Byte"],
            [1023, "1.0 kB"],
            [1024, "1.0 kB"],
            [1025, "1.0 kB"],
            [1000 * 1000, "1.0 MB"],
            [1000 * 1000 * 1000, "1.0 GB"],
            [1000 * 1000 * 1000 * 1000, "1.0 TB"],
            [1000 * 1000 * 1000 * 1000 * 1000, "1.0 PB"],
            [1000 * 1000 * 1000 * 1000 * 1000 * 1000, "1.0 EB"],
            [1000 * 1000 * 1000 * 1000 * 1000 * 1000 * 1000, "1.0 ZB"],
        ]:
            result = file_finder.ux.get_human_readable_number_of_bytes(
                sz, use_metric_system=True)
            self.assertEqual(expected, result)

    def test_get_human_readable_number_of_bytes_without_metric_system(self):
        for sz, expected in [
            [0, "0 Bytes"],
            [1, "1 Byte"],
            [1023, "1023 Bytes"],
            [1024, "1.0 KiB"],
            [1025, "1.0 KiB"],
            [1024 * 1024, "1.0 MiB"],
            [1024 * 1024 * 1024, "1.0 GiB"],
            [1024 * 1024 * 1024 * 1024, "1.0 TiB"],
            [1024 * 1024 * 1024 * 1024 * 1024, "1.0 PiB"],
            [1024 * 1024 * 1024 * 1024 * 1024 * 1024, "1.0 EiB"],
            [1024 * 1024 * 1024 * 1024 * 1024 * 1024 * 1024, "1.0 ZiB"],
        ]:
            result = file_finder.ux.get_human_readable_number_of_bytes(
                sz, use_metric_system=False)
            self.assertEqual(expected, result)

    def test_parse_human_readable_number_of_bytes_with_binary_multiples(self):
        for sz, expected in [
            ["0", 0],
            ["1024", 1024],
            ["1024.0", 1024],
            [f'{10 ** 6}', 10 ** 6],
            ["0 B", 0],
            ["1 B", 1],
            ["1023 B", 1023],
            ["1.0 KiB", 1024],
            ["1.0 MiB", 1024 * 1024],
            ["1.0 GiB", 1024 * 1024 * 1024],
            ["1.0 TiB", 1024 * 1024 * 1024 * 1024],
            ["1.0 PiB", 1024 * 1024 * 1024 * 1024 * 1024],
            ["1.0 EiB", 1024 * 1024 * 1024 * 1024 * 1024 * 1024],
            ["1.0 ZiB", 1024 * 1024 * 1024 * 1024 * 1024 * 1024 * 1024],
        ]:
            result = file_finder.ux.parse_human_readable_number_of_bytes(sz)
            self.assertEqual(expected, result)
