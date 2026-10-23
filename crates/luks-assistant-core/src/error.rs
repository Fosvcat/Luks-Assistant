use crate::i18n::Text;
use crate::tx;

#[derive(Debug)]
pub enum Error {
    Spawn {
        program: String,
        source: std::io::Error,
    },
    Command {
        program: String,
        code: i32,
        message: String,
    },
    Parse(Text),
    Blocked(Text),
    Unsupported(Text),
    Invalid(Text),
    Io(std::io::Error),
}

impl Error {
    /// The message, translated when shown.
    pub fn text(&self) -> Text {
        match self {
            Error::Spawn { program, source } => {
                tx!("无法启动 {}: {}", program, source.to_string())
            }
            Error::Command {
                program,
                code,
                message,
            } => tx!("{} 失败 (退出码 {}): {}", program, *code, message),
            Error::Parse(m) => tx!("解析失败: {}", m),
            Error::Blocked(m) => tx!("已阻止：{}", m),
            Error::Unsupported(m) => tx!("不支持: {}", m),
            Error::Invalid(m) => m.clone(),
            Error::Io(e) => Text::plain(e.to_string()),
        }
    }

    /// For logs, which are always English.
    pub fn en(&self) -> String {
        self.text().en()
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.text().fmt(f)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Spawn { source, .. } => Some(source),
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
