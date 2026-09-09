# frozen_string_literal: true

class MemoryExternalTransactions
  attr_reader :rows
  def initialize = @rows = {}

  def create_transaction(**attributes)
    @rows[attributes.fetch(:digest)] = Struct.new(*attributes.keys, :consumed_at).new(**attributes)
  end

  def transaction_by_digest(digest:) = @rows[digest]

  def consume_transaction(digest:, at:)
    row = @rows[digest]
    return false unless row && !row.consumed_at && row.issued_at <= at && row.expires_at > at
    row.consumed_at = at
    true
  end
end
