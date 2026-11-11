function(current) {
    if (!this.isConnected || (current !== undefined && this !== current)) return 'changed';
    for (let node=this; node; node=node.parentElement || (node.getRootNode().host || null)) {
        if (node.matches(':disabled') || (node.getAttribute('aria-disabled') || '').trim().toLowerCase()==='true') return 'disabled';
    }
    return null;
}
