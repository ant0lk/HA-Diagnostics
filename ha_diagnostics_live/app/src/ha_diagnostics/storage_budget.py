MiB=1024**2
def reserve_bytes(total):
    return min(12*MiB,total//4)
def archive_budget(total):
    return total-reserve_bytes(total)
def audit_budget(total):
    return min(8*MiB,reserve_bytes(total)*3//4)
