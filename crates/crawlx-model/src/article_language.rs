//! Pinned offline fastText lid.176 ONNX adapter, using the existing `ort` runtime.
//!
//! Weights are separate CC-BY-SA-3.0 resources, not relicensed as Rust source.
//! Mathematical featurization/postprocessing is independently implemented from the
//! pinned graph contract. No conversion-repository Python code is copied or executed.
//! A model card's 176 labels are not a measured 176-language quality claim.

use crawlx_core::{
    article_language::{
        ArticleLanguageDetector, LanguageDetectionErrorV1, LanguageDetectionV1, LanguageScoreV1,
    },
    hash::Digest,
};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use std::{collections::BTreeMap, fs::File, io::Read, path::Path};

/// Immutable source and license record, including every resource SHA-256.
pub const PINNED_MANIFEST: &str = include_str!("../data/lid176-onnx-v1.json");
const MAX_GRAPH_BYTES: u64 = 134_217_728;
const MAX_AUX_BYTES: u64 = 1_048_576;
const MAX_INPUT_BYTES: usize = 65_536;
const MAX_FEATURES: usize = 200_000;
const NWORDS: u32 = 40_010;
const BUCKETS: u32 = 2_000_000;
const LABELS: usize = 176;
const FILES: [(&str, &str); 6] = [
    (
        "lid176.onnx",
        "52a8a740a0c6a9b5a6ba0c384f4cc537893dfae6f3e7dca4ced23701ba772d2e",
    ),
    (
        "config.json",
        "deab42e22328633d964c8dcbfadee549a087a873646077fbd8a342d995731016",
    ),
    (
        "labels.json",
        "e42bc979dd04055bb02fc8194a05523904c66e535c1920f8f95008e33ab737cb",
    ),
    (
        "vocab.txt",
        "a89a468d0964645801fb3895b202e51b931980c3cc3b2f12a500166e4dc2810a",
    ),
    (
        "hs_tree.json",
        "b3a98e212804aa7b28b07b7b7cd5502066efa770ae674c8dfb734697d49d3d88",
    ),
    (
        "README.md",
        "e746899e5c6094e33b9924f0dfc35ea040fbd6c8875d3b8d1b91a6c2248884b3",
    ),
];
/// Language bundle admission failures retain causes but never article text.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ArticleLanguageError {
    /// Local operator-selected resource could not be read.
    #[error("language resource I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// A digest-verified auxiliary JSON record is malformed.
    #[error("language resource JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    /// Exact approved file bytes differ from the pinned source.
    #[error("language resource digest mismatch: {0}")]
    DigestMismatch(&'static str),
    /// Bounded resource/model contract failed.
    #[error("language model contract failed: {0}")]
    Contract(&'static str),
    /// Optional ONNX runtime is not installed or cannot load the approved graph.
    #[error("language model runtime unavailable")]
    Unavailable,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    dim: usize,
    minn: usize,
    maxn: usize,
    bucket: u32,
    nwords: u32,
    nlabels: usize,
    loss: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Tree {
    paths: Vec<Vec<usize>>,
    codes: Vec<Vec<bool>>,
}
/// The immutable resource identity used by native language policy.
#[must_use]
pub fn expected_bundle_digest() -> Digest {
    Digest::of("crawlx.article-language.bundle.v1", PINNED_MANIFEST.as_bytes())
}
fn read_verified(
    root: &Path,
    name: &'static str,
    expected: &str,
    limit: u64,
) -> Result<Vec<u8>, ArticleLanguageError> {
    use rustix::fs::{open, openat, Mode, OFlags};
    let directory = open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| ArticleLanguageError::Io(std::io::Error::from(error)))?;
    let descriptor = openat(
        &directory,
        name,
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| ArticleLanguageError::Io(std::io::Error::from(error)))?;
    let file = File::from(descriptor);
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(ArticleLanguageError::Contract("regular resource file/size"));
    }
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).map_err(|_| ArticleLanguageError::Contract("resource size"))? > limit {
        return Err(ArticleLanguageError::Contract("resource size"));
    }
    if hex::encode(Sha256::digest(&bytes)) != expected {
        return Err(ArticleLanguageError::DigestMismatch(name));
    }
    Ok(bytes)
}
/// Digest-verified local bundle. Loading never fetches or executes Python/code from the bundle.
pub struct PinnedLanguageBundle {
    model: Vec<u8>,
    vocabulary: BTreeMap<String, u32>,
    labels: Vec<String>,
    tree: Tree,
}
impl PinnedLanguageBundle {
    /// Open the exact pinned fp32 bundle from a trusted operator path.
    ///
    /// # Errors
    /// Rejects missing/symlink/oversize files, any digest mismatch or malformed tensor resources.
    pub fn open(root: &Path) -> Result<Self, ArticleLanguageError> {
        let mut resources = BTreeMap::new();
        for (name, sha) in FILES {
            let limit = if name == "lid176.onnx" {
                MAX_GRAPH_BYTES
            } else {
                MAX_AUX_BYTES
            };
            resources.insert(name, read_verified(root, name, sha, limit)?);
        }
        let config: Config = serde_json::from_slice(
            resources
                .get("config.json")
                .ok_or(ArticleLanguageError::Contract("config"))?,
        )?;
        if config.dim != 16
            || config.minn != 2
            || config.maxn != 4
            || config.bucket != BUCKETS
            || config.nwords != NWORDS
            || config.nlabels != LABELS
            || config.loss != "hs"
        {
            return Err(ArticleLanguageError::Contract("fixed fastText configuration"));
        }
        let raw_labels: Vec<String> = serde_json::from_slice(
            resources
                .get("labels.json")
                .ok_or(ArticleLanguageError::Contract("labels"))?,
        )?;
        let mut labels = Vec::with_capacity(LABELS);
        for label in raw_labels {
            let label = label
                .strip_prefix("__label__")
                .ok_or(ArticleLanguageError::Contract("label prefix"))?;
            if !(2..=3).contains(&label.len())
                || !label.bytes().all(|b| b.is_ascii_lowercase())
                || labels.iter().any(|previous| previous == label)
            {
                return Err(ArticleLanguageError::Contract("label vocabulary"));
            }
            labels.push(label.to_owned());
        }
        if labels.len() != LABELS {
            return Err(ArticleLanguageError::Contract("label count"));
        }
        let tree: Tree = serde_json::from_slice(
            resources
                .get("hs_tree.json")
                .ok_or(ArticleLanguageError::Contract("tree"))?,
        )?;
        if tree.paths.len() != LABELS
            || tree.codes.len() != LABELS
            || tree.paths.iter().zip(&tree.codes).any(|(path, codes)| {
                path.is_empty()
                    || path.len() != codes.len()
                    || path.len() > 32
                    || path.iter().any(|node| *node >= LABELS.saturating_sub(1))
            })
        {
            return Err(ArticleLanguageError::Contract("hierarchical-softmax paths"));
        }
        let raw_vocab = std::str::from_utf8(
            resources
                .get("vocab.txt")
                .ok_or(ArticleLanguageError::Contract("vocabulary"))?,
        )
        .map_err(|_| ArticleLanguageError::Contract("UTF-8 vocabulary"))?;
        let mut vocabulary = BTreeMap::new();
        for (index, word) in raw_vocab.lines().enumerate() {
            let index =
                u32::try_from(index).map_err(|_| ArticleLanguageError::Contract("vocabulary index"))?;
            if word.len() > 4096 || vocabulary.insert(word.to_owned(), index).is_some() {
                return Err(ArticleLanguageError::Contract("vocabulary entries"));
            }
        }
        if vocabulary.len()
            != usize::try_from(NWORDS).map_err(|_| ArticleLanguageError::Contract("vocabulary size"))?
            || !vocabulary.contains_key("</s>")
        {
            return Err(ArticleLanguageError::Contract("vocabulary count/EOS"));
        }
        let model = resources
            .remove("lid176.onnx")
            .ok_or(ArticleLanguageError::Contract("graph"))?;
        Ok(Self {
            model,
            vocabulary,
            labels,
            tree,
        })
    }
    /// Exact approved resource digest, independent of local path.
    #[must_use]
    pub fn digest(&self) -> Digest {
        expected_bundle_digest()
    }
    /// Borrow the verified serialized graph for an approved runtime without copying it.
    #[must_use]
    pub fn model_bytes(&self) -> &[u8] {
        &self.model
    }
    /// Produce bounded signed-byte UTF-8 n-gram IDs for the pinned graph.
    /// # Errors
    /// Returns a typed resource bound if the feature cap would be exceeded.
    pub fn features(&self, text: &str) -> Result<(Vec<i64>, bool), LanguageDetectionErrorV1> {
        let mut end = text.len().min(MAX_INPUT_BYTES);
        while !text.is_char_boundary(end) {
            end = end.saturating_sub(1);
        }
        let truncated = end < text.len();
        let mut features = Vec::new();
        for word in text[..end]
            .split(|ch: char| ch.is_ascii_whitespace() || ch == '\0')
            .filter(|word| !word.is_empty())
        {
            if let Some(id) = self.vocabulary.get(word) {
                features.push(i64::from(*id));
            }
            if word == "</s>" {
                continue;
            }
            let mut framed = String::with_capacity(word.len().saturating_add(2));
            framed.push('<');
            framed.push_str(word);
            framed.push('>');
            let starts: Vec<usize> = framed
                .char_indices()
                .map(|(index, _)| index)
                .chain(std::iter::once(framed.len()))
                .collect();
            for first in 0..starts.len().saturating_sub(1) {
                for length in 2..=4usize {
                    let last = first.saturating_add(length);
                    let Some(&finish) = starts.get(last) else {
                        break;
                    };
                    let hash = signed_fnv1a(&framed.as_bytes()[starts[first]..finish]);
                    features.push(i64::from(NWORDS.saturating_add(hash % BUCKETS)));
                    if features.len() >= MAX_FEATURES {
                        return Err(LanguageDetectionErrorV1::ResourceLimit);
                    }
                }
            }
        }
        let eos = self
            .vocabulary
            .get("</s>")
            .ok_or(LanguageDetectionErrorV1::Malformed)?;
        features.push(i64::from(*eos));
        if features.len() > MAX_FEATURES {
            return Err(LanguageDetectionErrorV1::ResourceLimit);
        }
        Ok((features, truncated))
    }
    /// Combine graph node sigmoid values using verified hierarchical-softmax paths.
    /// # Errors
    /// Rejects wrong shapes and non-finite/out-of-range probabilities.
    pub fn combine(
        &self,
        nodes: &[f32],
        truncated: bool,
    ) -> Result<LanguageDetectionV1, LanguageDetectionErrorV1> {
        if nodes.len() != LABELS || nodes.iter().any(|p| !p.is_finite() || !(0.0..=1.0).contains(p)) {
            return Err(LanguageDetectionErrorV1::Malformed);
        }
        let mut scores = Vec::with_capacity(LABELS);
        for (index, (path, codes)) in self.tree.paths.iter().zip(&self.tree.codes).enumerate() {
            let probability = path.iter().zip(codes).fold(1.0f64, |value, (&node, &right)| {
                let p = f64::from(nodes[node]);
                value * if right { p } else { 1.0 - p }
            });
            scores.push((
                index,
                LanguageScoreV1::new(self.labels[index].clone(), probability)?,
            ));
        }
        scores.sort_by(|(ia, a), (ib, b)| b.probability.total_cmp(&a.probability).then_with(|| ia.cmp(ib)));
        LanguageDetectionV1::new(
            self.digest(),
            scores.into_iter().map(|(_, score)| score).collect(),
            truncated,
        )
    }
}
fn signed_fnv1a(bytes: &[u8]) -> u32 {
    bytes.iter().fold(2_166_136_261u32, |hash, &byte| {
        let signed = i32::from(i8::from_ne_bytes([byte]));
        (hash ^ u32::from_ne_bytes(signed.to_ne_bytes())).wrapping_mul(16_777_619)
    })
}
/// Real local language backend. Optional runtime failure is explicit, never a fake classifier.
pub struct LocalArticleLanguage {
    bundle: PinnedLanguageBundle,
    #[cfg(feature = "onnx")]
    session: parking_lot::Mutex<ort::session::Session>,
}
impl LocalArticleLanguage {
    /// Load the verified graph into the existing ONNX Runtime, with one intra-op thread.
    /// # Errors
    /// Rejects missing runtime/feature and any malformed pinned resource or graph shape.
    pub fn open(root: &Path) -> Result<Self, ArticleLanguageError> {
        #[cfg(not(feature = "onnx"))]
        {
            let _ = root;
            Err(ArticleLanguageError::Unavailable)
        }
        #[cfg(feature = "onnx")]
        {
            let mut bundle = PinnedLanguageBundle::open(root)?;
            let dylib = std::env::var_os(crate::onnx_ranker::ORT_DYLIB_ENV)
                .filter(|value| !value.is_empty())
                .ok_or(ArticleLanguageError::Unavailable)?;
            ort::init_from(dylib)
                .map_err(|_| ArticleLanguageError::Unavailable)?
                .with_name("crawlx")
                .commit();
            let mut builder = ort::session::Session::builder()
                .map_err(|_| ArticleLanguageError::Unavailable)?
                .with_intra_threads(1)
                .map_err(|_| ArticleLanguageError::Unavailable)?;
            let session = builder
                .commit_from_memory(&bundle.model)
                .map_err(|_| ArticleLanguageError::Contract("ONNX graph"))?;
            if session.inputs().len() != 1
                || session.inputs()[0].name() != "input_ids"
                || session.outputs().len() != 1
                || session.outputs()[0].name() != "node_probs"
            {
                return Err(ArticleLanguageError::Contract("ONNX input/output names"));
            }
            // ORT owns its initialized graph; do not retain a second 125 MiB serialized copy.
            bundle.model.clear();
            bundle.model.shrink_to_fit();
            Ok(Self {
                bundle,
                session: parking_lot::Mutex::new(session),
            })
        }
    }
}
impl ArticleLanguageDetector for LocalArticleLanguage {
    fn bundle_digest(&self) -> Digest {
        self.bundle.digest()
    }
    fn detect(&self, text: &str) -> Result<LanguageDetectionV1, LanguageDetectionErrorV1> {
        if text.chars().filter(|ch| ch.is_alphabetic()).take(20).count() < 20 {
            return LanguageDetectionV1::new(self.bundle.digest(), Vec::new(), false);
        }
        #[cfg(not(feature = "onnx"))]
        {
            let _ = text;
            Err(LanguageDetectionErrorV1::Unavailable)
        }
        #[cfg(feature = "onnx")]
        {
            use ort::value::TensorRef;
            let (features, truncated) = self.bundle.features(text)?;
            let input = TensorRef::from_array_view(([features.len()], features.as_slice()))
                .map_err(|_| LanguageDetectionErrorV1::Malformed)?;
            let mut session = self.session.lock();
            let output = session
                .run(ort::inputs!["input_ids" => input])
                .map_err(|_| LanguageDetectionErrorV1::Malformed)?;
            let value = output
                .get("node_probs")
                .ok_or(LanguageDetectionErrorV1::Malformed)?;
            let (_, nodes) = value
                .try_extract_tensor::<f32>()
                .map_err(|_| LanguageDetectionErrorV1::Malformed)?;
            self.bundle.combine(nodes, truncated)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    #[test]
    fn verified_reader_refuses_symlinks_special_files_sizes_and_changed_bytes() {
        use rustix::fs::{mknodat, FileType, Mode, CWD};
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("regular"), b"approved").unwrap();
        symlink(root.path().join("regular"), root.path().join("link")).unwrap();
        mknodat(
            CWD,
            root.path().join("fifo"),
            FileType::Fifo,
            Mode::RUSR | Mode::WUSR,
            0,
        )
        .unwrap();
        assert!(read_verified(root.path(), "link", "", 100).is_err());
        assert!(read_verified(root.path(), "fifo", "", 100).is_err());
        assert!(read_verified(root.path(), "regular", "", 1).is_err());
        assert!(matches!(
            read_verified(root.path(), "regular", "0000", 100),
            Err(ArticleLanguageError::DigestMismatch("regular"))
        ));
        let sha = hex::encode(Sha256::digest(b"approved"));
        assert_eq!(
            read_verified(root.path(), "regular", &sha, 100).unwrap(),
            b"approved"
        );
    }
    #[cfg(feature = "onnx")]
    #[test]
    fn real_pinned_model_classifies_authored_heldout_prose_when_explicitly_installed() {
        let Some(root) = std::env::var_os("CRAWLX_TEST_ARTICLE_LANGUAGE_BUNDLE") else {
            return;
        };
        let detector = LocalArticleLanguage::open(Path::new(&root)).unwrap();
        let cases = [
            ("en", "The village library opened its reading room before sunrise. Volunteers carried wooden chairs into the garden and helped children choose books about rivers, birds, and distant planets."),
            ("fr", "La bibliothèque du village a ouvert sa salle de lecture avant le lever du soleil. Des bénévoles ont installé des chaises dans le jardin et aidé les enfants à choisir des livres sur les rivières et les oiseaux."),
            ("de", "Die Bibliothek im Dorf öffnete ihren Lesesaal vor Sonnenaufgang. Freiwillige trugen Holzstühle in den Garten und halfen den Kindern, Bücher über Flüsse und Vögel auszuwählen."),
            ("es", "La biblioteca del pueblo abrió su sala de lectura antes del amanecer. Los voluntarios llevaron sillas de madera al jardín y ayudaron a los niños a elegir libros sobre ríos y pájaros."),
            ("ja", "村の図書館は日の出前に閲覧室を開きました。ボランティアは木の椅子を庭に運び、子どもたちが川や鳥や遠い惑星についての本を選ぶのを手伝いました。"),
            ("hi", "गाँव के पुस्तकालय ने सूर्योदय से पहले अपना अध्ययन कक्ष खोला। स्वयंसेवकों ने लकड़ी की कुर्सियाँ बगीचे में रखीं और बच्चों को नदियों, पक्षियों और दूर के ग्रहों के बारे में किताबें चुनने में मदद की।"),
            ("th", "ห้องสมุดของหมู่บ้านเปิดห้องอ่านหนังสือก่อนพระอาทิตย์ขึ้น อาสาสมัครยกเก้าอี้ไม้ไปไว้ในสวนและช่วยเด็กเลือกหนังสือเกี่ยวกับแม่น้ำ นก และดาวเคราะห์ที่อยู่ห่างไกล"),
        ];
        for (language, text) in cases {
            let first = detector.detect(text).unwrap();
            let second = detector.detect(text).unwrap();
            assert_eq!(first, second);
            assert_eq!(first.scores.first().unwrap().language, language);
            assert_eq!(first.bundle_digest, expected_bundle_digest());
            assert!(!first.truncated);
        }
        assert!(detector.detect("123 ?").unwrap().scores.is_empty());
    }
}
