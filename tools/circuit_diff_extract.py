import re,sys
def strip(l):
    l=re.sub(r'"(\\.|[^"\\])*"','""',l); l=re.sub(r"'(\\.|[^'\\])'","''",l)
    return l.split('//',1)[0]
def func(path, start_pat, nth=0):
    L=open(path).read().split('\n')
    idx=[i for i,l in enumerate(L) if re.search(start_pat,l)][nth]
    depth=0; seen=False
    for j in range(idx,len(L)):
        for ch in strip(L[j]):
            if ch=='{': depth+=1; seen=True
            elif ch=='}': depth-=1
        if seen and depth==0: return idx+1, j+1, '\n'.join(L[idx:j+1])+'\n'
    raise SystemExit('unbalanced')
path,pat,out=sys.argv[1],sys.argv[2],sys.argv[3]
a,b,t=func(path,pat); open(out,'w').write(t); print(f'{path}:{a}-{b}')
