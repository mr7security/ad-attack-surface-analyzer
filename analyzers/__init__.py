from .kerberoast import KerberoastAnalyzer
from .asrep import ASREPAnalyzer
from .delegation import DelegationAnalyzer
from .acl import ACLAnalyzer
from .password_policy import PasswordPolicyAnalyzer
from .stale_accounts import StaleAccountsAnalyzer
from .privileged_groups import PrivilegedGroupsAnalyzer

ALL_ANALYZERS = [
    KerberoastAnalyzer, ASREPAnalyzer, DelegationAnalyzer,
    ACLAnalyzer, PasswordPolicyAnalyzer, StaleAccountsAnalyzer,
    PrivilegedGroupsAnalyzer,
]
