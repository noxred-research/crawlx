use ego_tree::Tree;

#[test]
fn try_reserve_grows_capacity_without_adding_nodes() {
    let mut tree = Tree::new(0u32);
    assert_eq!(tree.len(), 1);
    tree.try_reserve(100).unwrap();
    assert!(tree.capacity() >= 101);
    assert_eq!(tree.len(), 1, "reserving creates no node");
    let reserved = tree.capacity();
    for value in 1..=100 {
        tree.orphan(value);
    }
    assert_eq!(tree.len(), 101);
    assert_eq!(tree.capacity(), reserved, "nodes created within the reservation do not reallocate");
}

#[test]
fn try_reserve_reports_failure_and_keeps_the_tree() {
    let mut tree = Tree::new(0u64);
    tree.root_mut().append(1);
    assert!(tree.try_reserve(usize::MAX).is_err());
    assert!(tree.try_reserve_exact(usize::MAX).is_err());
    assert_eq!(tree.len(), 2);
    assert_eq!(tree.root().first_child().map(|child| *child.value()), Some(1));
}

#[test]
fn node_size_matches_the_stored_unit() {
    assert!(Tree::<()>::node_size() >= 5 * core::mem::size_of::<usize>());
    assert!(Tree::<[u8; 64]>::node_size() >= Tree::<()>::node_size() + 64);
}
