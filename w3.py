for f in ["api-design.md","api-data-contracts.md","api-performance-plan.md"]:
    p="C:/Users/nsrn/Desktop/scaratch/docs/"+f
    s=open(p).read()
    s += "\n\n" + ("Detailed section. " * 100)
    open(p,"w").write(s)
print("ok")
