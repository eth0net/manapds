//! The Merkle search tree that holds an account's records.
//!
//! A key's depth is the number of leading zero pairs of bits in the sha-256 of
//! it, so where a record sits is a function of its name and nothing else. Two
//! servers given the same records build the same tree and hash to the same
//! root, which is what makes repositories diffable at all.

use ipld_core::cid::Cid;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use std::cell::{Cell, RefCell};
use std::collections::BTreeSet;

use super::{BlockMap, Error, Store, cid_for, encode, read};

/// Deeper than the depth rule can put a node: a key's layer is the leading
/// zero pairs of a sha-256, so 128 is the ceiling and anything past it is a
/// tree built by hand.
const MAX_DEPTH: usize = 256;

/// One traversal's view of the store.
///
/// A well-formed tree is a tree, so no node is reached twice and none sits
/// deeper than its keys allow. Holding both on the way in means neither the
/// stack nor the clock depends on what a stored node claims about its
/// children — a file whose nodes point at each other is refused rather than
/// walked, however small it is.
struct Reader<'a> {
    store: &'a dyn Store,
    depth: Cell<usize>,
    seen: RefCell<BTreeSet<Cid>>,
}

impl<'a> Reader<'a> {
    fn new(store: &'a dyn Store) -> Self {
        Self {
            store,
            depth: Cell::new(0),
            seen: RefCell::new(BTreeSet::new()),
        }
    }

    fn contains(&self, cid: &Cid) -> Result<bool, Error> {
        self.store.contains(cid)
    }

    /// Reads a node, refusing one this traversal has already been through.
    fn node(&self, cid: &Cid) -> Result<NodeData, Error> {
        if !self.seen.borrow_mut().insert(*cid) {
            return Err(Error::MalformedNode("a node under itself"));
        }
        read(self.store, cid)
    }

    /// Counts a level, and gives it back when the frame ends.
    fn descend(&self) -> Result<Descent<'_>, Error> {
        let depth = self.depth.get() + 1;
        if depth > MAX_DEPTH {
            return Err(Error::MalformedNode("a tree deeper than its keys allow"));
        }
        self.depth.set(depth);
        Ok(Descent(self))
    }
}

struct Descent<'a>(&'a Reader<'a>);

impl Drop for Descent<'_> {
    fn drop(&mut self) {
        self.0.depth.set(self.0.depth.get() - 1);
    }
}

/// The longest key the tree will hold, counting the collection and the slash.
const MAX_KEY_LEN: usize = 1024;

/// A node as it is stored: the leftmost subtree, then the entries.
#[derive(Debug, Deserialize, Serialize)]
struct NodeData {
    l: Option<Cid>,
    e: Vec<TreeEntry>,
}

/// One leaf and the subtree to its right, with the key compressed against the
/// key before it because neighbors in a node share most of their prefix.
#[derive(Debug, Deserialize, Serialize)]
struct TreeEntry {
    p: usize,
    #[serde(with = "serde_bytes")]
    k: Vec<u8>,
    v: Cid,
    t: Option<Cid>,
}

/// A record, under the `<collection>/<rkey>` key it is found by.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Leaf {
    /// Where the record lives in the repository.
    pub key: String,
    /// The block the record itself is in.
    pub value: Cid,
}

#[derive(Clone, Debug)]
enum Entry {
    Leaf(Leaf),
    Tree(Mst),
}

/// A subtree, loaded from the reader only as far as an operation reaches.
///
/// Every operation that changes the tree takes it and gives back the changed
/// one, because a node's identity is its contents: nothing is edited in place
/// further down than the hash is recomputed.
#[derive(Clone, Debug)]
pub struct Mst {
    /// `None` until the node is read from the reader.
    entries: Option<Vec<Entry>>,
    /// `None` until a key in this node, or under it, gives it away.
    layer: Option<usize>,
    /// `None` once the contents have moved on from the hash.
    pointer: Option<Cid>,
}

impl Mst {
    /// A tree with nothing in it.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            entries: Some(Vec::new()),
            layer: None,
            pointer: None,
        }
    }

    /// The tree under a root CID, read on demand.
    #[must_use]
    pub fn load(root: Cid) -> Self {
        Self {
            entries: None,
            layer: None,
            pointer: Some(root),
        }
    }

    /// The CID of this node, hashing it and everything under it that has
    /// changed.
    ///
    /// # Errors
    ///
    /// If a block it reaches for is missing, or will not encode.
    pub fn root(&mut self, store: &dyn Store) -> Result<Cid, Error> {
        self.root_in(&Reader::new(store))
    }

    fn root_in(&mut self, reader: &Reader<'_>) -> Result<Cid, Error> {
        let _descent = reader.descend()?;
        if let Some(cid) = self.pointer {
            return Ok(cid);
        }
        let data = self.node_data(reader)?;
        let cid = cid_for(&encode(&data)?);
        self.pointer = Some(cid);
        Ok(cid)
    }

    /// The block for a record, or `None` if the tree does not hold that key.
    ///
    /// # Errors
    ///
    /// If a block it reaches for is missing.
    pub fn get(&mut self, store: &dyn Store, key: &str) -> Result<Option<Cid>, Error> {
        self.get_in(&Reader::new(store), key)
    }

    fn get_in(&mut self, reader: &Reader<'_>, key: &str) -> Result<Option<Cid>, Error> {
        let _descent = reader.descend()?;
        let index = self.index_of(reader, key)?;
        let entries = self.entries(reader)?;
        if let Some(Entry::Leaf(leaf)) = entries.get(index)
            && leaf.key == key
        {
            return Ok(Some(leaf.value));
        }
        match index.checked_sub(1).and_then(|i| entries.get_mut(i)) {
            Some(Entry::Tree(subtree)) => subtree.get_in(reader, key),
            _ => Ok(None),
        }
    }

    /// Adds a record at a key nothing holds yet.
    ///
    /// # Errors
    ///
    /// If the key is not a record path, is already taken, or a block it
    /// reaches for is missing.
    pub fn add(self, store: &dyn Store, key: &str, value: Cid) -> Result<Self, Error> {
        self.add_in(&Reader::new(store), key, value)
    }

    fn add_in(self, reader: &Reader<'_>, key: &str, value: Cid) -> Result<Self, Error> {
        ensure_valid_key(key)?;
        self.insert(reader, key, value, leading_zeros(key.as_bytes()))
    }

    /// Points an existing key at a different record.
    ///
    /// # Errors
    ///
    /// If the key is not a record path, is not in the tree, or a block it
    /// reaches for is missing.
    pub fn update(self, store: &dyn Store, key: &str, value: Cid) -> Result<Self, Error> {
        self.update_in(&Reader::new(store), key, value)
    }

    fn update_in(mut self, reader: &Reader<'_>, key: &str, value: Cid) -> Result<Self, Error> {
        let _descent = reader.descend()?;
        ensure_valid_key(key)?;
        let index = self.index_of(reader, key)?;
        let layer = self.layer;
        let mut entries = self.take_entries(reader)?;
        if let Some(Entry::Leaf(leaf)) = entries.get_mut(index)
            && leaf.key == key
        {
            leaf.value = value;
            return Ok(Self::from_entries(entries, layer));
        }
        let Some(i) = index
            .checked_sub(1)
            .filter(|&i| matches!(entries[i], Entry::Tree(_)))
        else {
            return Err(Error::KeyMissing(key.to_owned()));
        };
        let Entry::Tree(subtree) = entries.remove(i) else {
            unreachable!("just matched a subtree")
        };
        entries.insert(i, Entry::Tree(subtree.update_in(reader, key, value)?));
        Ok(Self::from_entries(entries, layer))
    }

    /// Takes a record out, collapsing any node the removal leaves spare.
    ///
    /// # Errors
    ///
    /// If the key is not in the tree, or a block it reaches for is missing.
    pub fn delete(self, store: &dyn Store, key: &str) -> Result<Self, Error> {
        self.delete_in(&Reader::new(store), key)
    }

    fn delete_in(self, reader: &Reader<'_>, key: &str) -> Result<Self, Error> {
        self.delete_recurse(reader, key)?.trim_top(reader)
    }

    /// Every record in the tree, in key order.
    ///
    /// # Errors
    ///
    /// If a block it reaches for is missing.
    pub fn leaves(&mut self, store: &dyn Store) -> Result<Vec<Leaf>, Error> {
        self.leaves_in(&Reader::new(store))
    }

    fn leaves_in(&mut self, reader: &Reader<'_>) -> Result<Vec<Leaf>, Error> {
        let mut found = Vec::new();
        self.collect_leaves(reader, &mut found)?;
        Ok(found)
    }

    /// The blocks that would have to be written to reader this tree, and the
    /// root they hang from.
    ///
    /// # Errors
    ///
    /// If a block it reaches for is missing, or will not encode.
    pub fn unstored_blocks(&mut self, store: &dyn Store) -> Result<(Cid, BlockMap), Error> {
        self.unstored_blocks_in(&Reader::new(store))
    }

    fn unstored_blocks_in(&mut self, reader: &Reader<'_>) -> Result<(Cid, BlockMap), Error> {
        let _descent = reader.descend()?;
        let mut blocks = BlockMap::new();
        let root = self.root_in(reader)?;
        if reader.contains(&root)? {
            return Ok((root, blocks));
        }
        let data = self.node_data(reader)?;
        blocks.add(&data)?;
        for entry in self.entries(reader)? {
            if let Entry::Tree(subtree) = entry {
                blocks.merge(subtree.unstored_blocks_in(reader)?.1);
            }
        }
        Ok((root, blocks))
    }

    // Building
    // --------

    fn from_entries(entries: Vec<Entry>, layer: Option<usize>) -> Self {
        Self {
            entries: Some(entries),
            layer,
            pointer: None,
        }
    }

    fn insert(
        mut self,
        reader: &Reader<'_>,
        key: &str,
        value: Cid,
        zeros: usize,
    ) -> Result<Self, Error> {
        let layer = self.layer(reader)?;
        if zeros > layer {
            // The key sits above everything here, so the whole tree becomes
            // the two halves either side of it.
            let (mut left, mut right) = self.split_around(reader, key)?;
            for _ in 1..(zeros - layer) {
                left = left.map(Self::into_parent).transpose()?;
                right = right.map(Self::into_parent).transpose()?;
            }
            let mut entries = Vec::new();
            entries.extend(left.map(Entry::Tree));
            entries.push(Entry::Leaf(Leaf {
                key: key.to_owned(),
                value,
            }));
            entries.extend(right.map(Entry::Tree));
            return Ok(Self::from_entries(entries, Some(zeros)));
        }

        let index = self.index_of(reader, key)?;
        let mut entries = self.take_entries(reader)?;
        let prev = index
            .checked_sub(1)
            .filter(|&i| matches!(entries[i], Entry::Tree(_)));

        if zeros < layer {
            // It belongs under the subtree to the left, or under a new one.
            let subtree = match prev {
                Some(i) => {
                    let Entry::Tree(subtree) = entries.remove(i) else {
                        unreachable!("just matched a subtree")
                    };
                    subtree
                }
                None => Self::from_entries(Vec::new(), Some(layer - 1)),
            };
            let at = prev.unwrap_or(index);
            let grown = subtree.insert(reader, key, value, zeros)?;
            entries.insert(at, Entry::Tree(grown));
            return Ok(Self::from_entries(entries, Some(layer)));
        }

        if matches!(entries.get(index), Some(Entry::Leaf(leaf)) if leaf.key == key) {
            return Err(Error::KeyExists(key.to_owned()));
        }
        let leaf = Entry::Leaf(Leaf {
            key: key.to_owned(),
            value,
        });
        match prev {
            // The subtree to the left spans the key, so it has to be cut in two
            // and the leaf laid between the halves.
            Some(i) => {
                let Entry::Tree(subtree) = entries.remove(i) else {
                    unreachable!("just matched a subtree")
                };
                let (left, right) = subtree.split_around(reader, key)?;
                let split = left
                    .map(Entry::Tree)
                    .into_iter()
                    .chain([leaf])
                    .chain(right.map(Entry::Tree));
                entries.splice(i..i, split);
            }
            None => entries.insert(index, leaf),
        }
        Ok(Self::from_entries(entries, Some(layer)))
    }

    fn delete_recurse(mut self, reader: &Reader<'_>, key: &str) -> Result<Self, Error> {
        let _descent = reader.descend()?;
        let index = self.index_of(reader, key)?;
        let layer = self.layer;
        let mut entries = self.take_entries(reader)?;

        if matches!(entries.get(index), Some(Entry::Leaf(leaf)) if leaf.key == key) {
            let between = index.checked_sub(1).is_some_and(|i| {
                matches!(entries[i], Entry::Tree(_))
                    && matches!(entries.get(index + 1), Some(Entry::Tree(_)))
            });
            if between {
                let Entry::Tree(right) = entries.remove(index + 1) else {
                    unreachable!("just matched a subtree")
                };
                entries.remove(index);
                let Entry::Tree(left) = entries.remove(index - 1) else {
                    unreachable!("just matched a subtree")
                };
                entries.insert(index - 1, Entry::Tree(left.append_merge(reader, right)?));
            } else {
                entries.remove(index);
            }
            return Ok(Self::from_entries(entries, layer));
        }

        let Some(i) = index
            .checked_sub(1)
            .filter(|&i| matches!(entries[i], Entry::Tree(_)))
        else {
            return Err(Error::KeyMissing(key.to_owned()));
        };
        let Entry::Tree(subtree) = entries.remove(i) else {
            unreachable!("just matched a subtree")
        };
        let mut shrunk = subtree.delete_recurse(reader, key)?;
        if !shrunk.entries(reader)?.is_empty() {
            entries.insert(i, Entry::Tree(shrunk));
        }
        Ok(Self::from_entries(entries, layer))
    }

    /// Drops any node that has become a lone pointer at the node below it.
    fn trim_top(mut self, reader: &Reader<'_>) -> Result<Self, Error> {
        let _descent = reader.descend()?;
        match self.fill(reader) {
            // A tree read from a proof stops where the proof does, and a top
            // that cannot be read is a top that cannot be trimmed.
            Err(Error::MissingBlock(_)) => return Ok(self),
            Err(error) => return Err(error),
            Ok(()) => {}
        }
        if matches!(self.entries.as_deref(), Some([Entry::Tree(_)])) {
            let Entry::Tree(subtree) = self.take_entries(reader)?.remove(0) else {
                unreachable!("just matched a subtree")
            };
            return subtree.trim_top(reader);
        }
        Ok(self)
    }

    /// Splits into everything below the key and everything above it, cutting
    /// through any subtree the key falls inside.
    fn split_around(
        mut self,
        reader: &Reader<'_>,
        key: &str,
    ) -> Result<(Option<Self>, Option<Self>), Error> {
        let index = self.index_of(reader, key)?;
        let layer = self.layer;
        let mut left = self.take_entries(reader)?;
        let mut right = left.split_off(index);

        if matches!(left.last(), Some(Entry::Tree(_))) {
            let Some(Entry::Tree(subtree)) = left.pop() else {
                unreachable!("just matched a subtree")
            };
            let (below, above) = subtree.split_around(reader, key)?;
            left.extend(below.map(Entry::Tree));
            if let Some(above) = above {
                right.insert(0, Entry::Tree(above));
            }
        }

        Ok((
            (!left.is_empty()).then(|| Self::from_entries(left, layer)),
            (!right.is_empty()).then(|| Self::from_entries(right, layer)),
        ))
    }

    /// Joins two nodes of the same layer where every key on the right is above
    /// every key on the left.
    fn append_merge(mut self, reader: &Reader<'_>, mut other: Self) -> Result<Self, Error> {
        let _descent = reader.descend()?;
        if self.layer(reader)? != other.layer(reader)? {
            return Err(Error::MalformedNode(
                "merged two nodes from different layers",
            ));
        }
        let layer = self.layer;
        let mut left = self.take_entries(reader)?;
        let mut right = other.take_entries(reader)?;
        if matches!(left.last(), Some(Entry::Tree(_)))
            && matches!(right.first(), Some(Entry::Tree(_)))
        {
            let (Some(Entry::Tree(inner_left)), Entry::Tree(inner_right)) =
                (left.pop(), right.remove(0))
            else {
                unreachable!("just matched two subtrees")
            };
            left.push(Entry::Tree(inner_left.append_merge(reader, inner_right)?));
        }
        left.append(&mut right);
        Ok(Self::from_entries(left, layer))
    }

    fn into_parent(self) -> Result<Self, Error> {
        let layer = self
            .layer
            .ok_or(Error::MalformedNode("raised a node of unknown layer"))?;
        Ok(Self::from_entries(vec![Entry::Tree(self)], Some(layer + 1)))
    }

    // Reading
    // -------

    /// Reads this node in, if it has not been read yet.
    fn fill(&mut self, reader: &Reader<'_>) -> Result<(), Error> {
        if self.entries.is_some() {
            return Ok(());
        }
        let cid = self
            .pointer
            .ok_or(Error::MalformedNode("a node with neither contents nor CID"))?;
        let data: NodeData = reader.node(&cid)?;
        // The first entry shares no prefix, so its stored key is the whole one
        // and gives the layer away.
        let layer = data.e.first().map(|entry| leading_zeros(&entry.k));
        self.entries = Some(deserialize(&data, layer)?);
        Ok(())
    }

    fn entries(&mut self, reader: &Reader<'_>) -> Result<&mut Vec<Entry>, Error> {
        self.fill(reader)?;
        Ok(self.entries.as_mut().expect("just filled"))
    }

    fn take_entries(&mut self, reader: &Reader<'_>) -> Result<Vec<Entry>, Error> {
        self.fill(reader)?;
        self.pointer = None;
        Ok(self.entries.take().expect("just filled"))
    }

    fn layer(&mut self, reader: &Reader<'_>) -> Result<usize, Error> {
        let layer = self.find_layer(reader)?.unwrap_or(0);
        self.layer = Some(layer);
        Ok(layer)
    }

    /// The layer, from the first key at this level or under it.
    fn find_layer(&mut self, reader: &Reader<'_>) -> Result<Option<usize>, Error> {
        let _descent = reader.descend()?;
        if self.layer.is_some() {
            return Ok(self.layer);
        }
        let entries = self.entries(reader)?;
        let mut layer = entries.iter().find_map(|entry| match entry {
            Entry::Leaf(leaf) => Some(leading_zeros(leaf.key.as_bytes())),
            Entry::Tree(_) => None,
        });
        if layer.is_none() {
            for entry in entries.iter_mut() {
                if let Entry::Tree(subtree) = entry
                    && let Some(under) = subtree.find_layer(reader)?
                {
                    layer = Some(under + 1);
                    break;
                }
            }
        }
        self.layer = layer;
        Ok(layer)
    }

    /// Where the first key at or above this one sits, or the end of the node.
    fn index_of(&mut self, reader: &Reader<'_>, key: &str) -> Result<usize, Error> {
        let entries = self.entries(reader)?;
        Ok(entries
            .iter()
            .position(|entry| matches!(entry, Entry::Leaf(leaf) if leaf.key.as_str() >= key))
            .unwrap_or(entries.len()))
    }

    fn collect_leaves(&mut self, reader: &Reader<'_>, found: &mut Vec<Leaf>) -> Result<(), Error> {
        let _descent = reader.descend()?;
        for entry in self.entries(reader)? {
            match entry {
                Entry::Leaf(leaf) => found.push(leaf.clone()),
                Entry::Tree(subtree) => subtree.collect_leaves(reader, found)?,
            }
        }
        Ok(())
    }

    /// This node as it is stored, with every subtree's CID settled first.
    fn node_data(&mut self, reader: &Reader<'_>) -> Result<NodeData, Error> {
        serialize(self.entries(reader)?, reader)
    }
}

fn serialize(entries: &mut [Entry], reader: &Reader<'_>) -> Result<NodeData, Error> {
    let mut data = NodeData {
        l: None,
        e: Vec::new(),
    };
    let mut index = 0;
    if let Some(Entry::Tree(subtree)) = entries.first_mut() {
        data.l = Some(subtree.root_in(reader)?);
        index = 1;
    }
    let mut last = String::new();
    while index < entries.len() {
        let Entry::Leaf(leaf) = &entries[index] else {
            return Err(Error::MalformedNode("two subtrees side by side"));
        };
        let (key, value) = (leaf.key.clone(), leaf.value);
        index += 1;
        let mut subtree = None;
        if let Some(Entry::Tree(right)) = entries.get_mut(index) {
            subtree = Some(right.root_in(reader)?);
            index += 1;
        }
        ensure_valid_key(&key)?;
        let prefix = shared_prefix(&last, &key);
        data.e.push(TreeEntry {
            p: prefix,
            k: key.as_bytes()[prefix..].to_vec(),
            v: value,
            t: subtree,
        });
        last = key;
    }
    Ok(data)
}

fn deserialize(data: &NodeData, layer: Option<usize>) -> Result<Vec<Entry>, Error> {
    let under = layer.and_then(|layer| layer.checked_sub(1));
    let mut entries = Vec::new();
    if let Some(cid) = data.l {
        entries.push(Entry::Tree(Mst {
            entries: None,
            layer: under,
            pointer: Some(cid),
        }));
    }
    let mut last = String::new();
    for entry in &data.e {
        let suffix =
            str::from_utf8(&entry.k).map_err(|_| Error::MalformedNode("a key that is not text"))?;
        let shared = last.get(..entry.p).ok_or(Error::MalformedNode(
            "a prefix longer than the key before it",
        ))?;
        let key = format!("{shared}{suffix}");
        ensure_valid_key(&key)?;
        entries.push(Entry::Leaf(Leaf {
            key: key.clone(),
            value: entry.v,
        }));
        last = key;
        if let Some(cid) = entry.t {
            entries.push(Entry::Tree(Mst {
                entries: None,
                layer: under,
                pointer: Some(cid),
            }));
        }
    }
    Ok(entries)
}

/// How deep a key sits: the leading zero bits of its hash, counted in pairs.
fn leading_zeros(key: &[u8]) -> usize {
    let mut zeros = 0;
    for byte in Sha256::digest(key) {
        zeros += byte.leading_zeros() as usize / 2;
        if byte != 0 {
            break;
        }
    }
    zeros
}

fn shared_prefix(a: &str, b: &str) -> usize {
    a.bytes().zip(b.bytes()).take_while(|(a, b)| a == b).count()
}

fn ensure_valid_key(key: &str) -> Result<(), Error> {
    let mut parts = key.split('/');
    let valid = match (parts.next(), parts.next(), parts.next()) {
        (Some(collection), Some(rkey), None) => {
            key.len() <= MAX_KEY_LEN
                && !collection.is_empty()
                && !rkey.is_empty()
                && key.bytes().all(|byte| byte == b'/' || is_key_byte(byte))
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(Error::InvalidKey(key.to_owned()))
    }
}

fn is_key_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'~' | b'-' | b':' | b'.')
}
