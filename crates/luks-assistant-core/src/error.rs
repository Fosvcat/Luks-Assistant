use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("无法启动 {program}: {source}")]
    Spawn {
        program: String,
        source: std::io::Error,
    },
    #[error("{program} 失败 (退出码 {code}): {message}")]
    Command {
        program: String,
        code: i32,
        message: String,
    },
    #[error("解析失败: {0}")]
    Parse(String),
    #[error("被安全规则阻止: {0}")]
    Blocked(String),
    #[error("不支持: {0}")]
    Unsupported(String),
    #[error("{0}")]
    Invalid(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
