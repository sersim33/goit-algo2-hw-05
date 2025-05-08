import json
import time
import mmh3
import math


class HyperLogLog:
    def __init__(self, p=14):
        self.p = p
        self.m = 1 << p
        self.registers = [0] * self.m
        self.alpha = self._get_alpha()
        self.small_range_correction = 5 * self.m / 2

    def _get_alpha(self):
        if self.p <= 16:
            return 0.673
        elif self.p == 32:
            return 0.697
        else:
            return 0.7213 / (1 + 1.079 / self.m)

    def add(self, item):
        x = mmh3.hash(str(item), signed=False)
        j = x & (self.m - 1)
        w = x >> self.p
        self.registers[j] = max(self.registers[j], self._rho(w))

    def _rho(self, w):
        return len(bin(w)) - 2 if w > 0 else 32

    def count(self):
        Z = sum(2.0 ** -r for r in self.registers)
        E = self.alpha * self.m * self.m / Z

        if E <= self.small_range_correction:
            V = self.registers.count(0)
            if V > 0:
                return self.m * math.log(self.m / V)

        return E


def extract_ips_from_log(filepath):
    """Генерує IP-адреси з лог-файлу"""
    with open(filepath, "r") as file:
        for line in file:
            try:
                log_entry = json.loads(line)
                ip = log_entry.get("remote_addr")
                if ip:
                    yield ip
            except json.JSONDecodeError:
                continue


if __name__ == "__main__":
    filepath = "/content/lms-stage-access.log"

    # HyperLogLog
    hll = HyperLogLog(p=14)
    start_time = time.time()
    for ip in extract_ips_from_log(filepath):
        hll.add(ip)
    hll_time = time.time() - start_time
    hll_count = hll.count()

    # Точний підрахунок через set
    ip_set = set()
    start_time = time.time()
    for ip in extract_ips_from_log(filepath):
        ip_set.add(ip)
    set_time = time.time() - start_time
    set_count = len(ip_set)

    # Порівняння
    print(f"\n[HyperLogLog] Оцінено унікальних IP: {int(hll_count)} — Час: {hll_time:.4f} сек")
    print(f"[Set         ] Точно унікальних IP: {set_count} — Час: {set_time:.4f} сек")
    print(f"Відхилення оцінки: {abs(set_count - hll_count) / set_count * 100:.2f}%")
