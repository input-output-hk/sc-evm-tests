from datetime import datetime
from typing import Optional
from sqlalchemy import String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class OutgoingTransaction(Base):
    __tablename__ = "outgoing_transactions"
    id: Mapped[int] = mapped_column(primary_key=True)
    sender: Mapped[str] = mapped_column(String(255))
    recipient: Mapped[str] = mapped_column(String(255))
    recipient_bech32: Mapped[str] = mapped_column(String(255))
    value: Mapped[str] = mapped_column(String(100))
    tx_index: Mapped[Optional[int]]
    epoch: Mapped[Optional[int]]
    merkle_proof: Mapped[Optional[str]] = mapped_column(String(2000))
    is_claimed: Mapped[bool] = mapped_column(insert_default=False)
    lock_timestamp: Mapped[Optional[datetime]]
    claim_start_timestamp: Mapped[Optional[datetime]]
    claim_end_timestamp: Mapped[Optional[datetime]]
    skey_file_path: Mapped[Optional[str]] = mapped_column(String(1000))

    def __repr__(self) -> str:
        merkle_proof_trunc = None
        if self.merkle_proof and len(self.merkle_proof) > 16:
            merkle_proof_trunc = f"...{self.merkle_proof[-16:]}"
        return (
            f"OutgoingTransaction(id={self.id}, "
            f"sender={self.sender}, recipient={self.recipient}, "
            f"value={self.value}, tx_index={self.tx_index}, "
            f"epoch={self.epoch}, is_claimed={self.is_claimed}, "
            f"merkle_proof={merkle_proof_trunc})"
        )

    def __repr_short__(self) -> str:
        return (
            f"OutgoingTransaction(id={self.id}, "
            f"value={self.value}, tx_index={self.tx_index}, "
            f"epoch={self.epoch})"
        )
