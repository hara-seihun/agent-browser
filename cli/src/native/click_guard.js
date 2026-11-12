(target, current) => {
    if (!target.isConnected || (current !== undefined && target !== current)) return 'changed';
    for (let node=target; node; node=node.parentElement || (node.getRootNode().host || null)) {
        if (node.matches(':disabled') || (node.getAttribute('aria-disabled') || '').trim().toLowerCase()==='true') return 'disabled';
    }
    return null;
}
