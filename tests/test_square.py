import unittest

from midsig.postage.policy import CARD_CENTS, CARD_MIN_CENTS, payer_address, Rejected
from midsig.postage import square as squarepay


class SquarePolicyTests(unittest.TestCase):
    def test_card_minimum_is_ten_dollars(self):
        self.assertEqual(CARD_MIN_CENTS, 1000)
        self.assertEqual(squarepay.cents_for("ten"), 1000)
        self.assertEqual(squarepay.cents_for("stack"), 2500)
        with self.assertRaises(Rejected):
            squarepay.cents_for("starter")

    def test_square_payer_is_not_a_chain_address(self):
        self.assertEqual(payer_address("square", "ignored"), "square:card")
