import os
import tempfile
import pytest
from venom.interface import InterfaceModeler, find_function_at_line


SAMPLE_C = """\
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void process_input(const char *data) {
    char buf[64];
    strcpy(buf, data);
    printf("%s", buf);
}

int safe_copy(char *dst, const char *src, size_t n) {
    memcpy(dst, src, n);
    return 0;
}

int main(int argc, char **argv) {
    char *input = malloc(1024);
    if (!input) return 1;
    read(0, input, 1024);
    process_input(input);
    free(input);
    return 0;
}
"""


@pytest.fixture
def sample_file(tmp_path):
    p = tmp_path / "sample.c"
    p.write_text(SAMPLE_C)
    return str(p)


class TestInterfaceModeler:
    def test_analyze_file(self, sample_file):
        m = InterfaceModeler()
        iface = m.analyze_file(sample_file)
        assert "process_input" in iface["functions"]
        assert "safe_copy" in iface["functions"]
        assert "main" in iface["functions"]

    def test_entry_points(self, sample_file):
        m = InterfaceModeler()
        iface = m.analyze_file(sample_file)
        assert "main" in iface["entry_points"]

    def test_taint_sources(self, sample_file):
        m = InterfaceModeler()
        m.analyze_file(sample_file)
        taint = m.get_function_taint("main")
        assert "read" in taint["sources"] or "malloc" in taint["sinks"]

    def test_taint_sinks(self, sample_file):
        m = InterfaceModeler()
        m.analyze_file(sample_file)
        taint = m.get_function_taint("process_input")
        assert "strcpy" in taint["sinks"] or "printf" in taint["sinks"]

    def test_call_graph(self, sample_file):
        m = InterfaceModeler()
        m.analyze_file(sample_file)
        callees = m.get_callees("main")
        assert "process_input" in callees

    def test_function_locations(self, sample_file):
        m = InterfaceModeler()
        m.analyze_file(sample_file)
        assert "main" in m.function_locations
        assert m.function_locations["main"]["file"] == sample_file

    def test_nonexistent_file(self):
        m = InterfaceModeler()
        result = m.analyze_file("/nonexistent/file.c")
        assert result == {}


class TestFindFunctionAtLine:
    def test_finds_function(self, sample_file):
        assert find_function_at_line(sample_file, 7) == "process_input"
        assert find_function_at_line(sample_file, 13) == "safe_copy"

    def test_main(self, sample_file):
        assert find_function_at_line(sample_file, 20) == "main"

    def test_nonexistent(self):
        assert find_function_at_line("/no/such/file.c", 1) is None
