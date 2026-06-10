#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NodeRole {
    Validator,

    Full,
}

impl NodeRole {
    pub const fn is_validator(self) -> bool {
        matches!(self, NodeRole::Validator)
    }

    pub const fn is_full(self) -> bool {
        matches!(self, NodeRole::Full)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            NodeRole::Validator => "validator",
            NodeRole::Full => "full",
        }
    }
}
