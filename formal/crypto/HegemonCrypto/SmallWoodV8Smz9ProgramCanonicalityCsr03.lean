import HegemonCrypto.SmallWoodV8Smz9ProgramCanonicalityCsr02

/-! Generated bounded CSR certificates; each chunk has at most 32 attempts. -/
namespace HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr03
open Hegemon.Transaction.Poseidon2V8RelationProgram
open HegemonCrypto.SmallWood.V8Smz9RelationProgramComponentsGenerated
open HegemonCrypto.SmallWood.V8Smz9ProgramCanonicality
set_option Elab.async false
set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def counters000 : List Nat := [1536, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
def chunk000 : List CsrExecutableAttempt :=
  [attempt 1536 0 1536 0 [(1561, 1), (1536, 3)] 0, attempt 1537 0 1537 0 [(1562, 1), (1536, 3)] 0, attempt 1538 0 1538 0 [(1563, 1), (1536, 3)] 0, attempt 1539 0 1539 0 [(1564, 1), (1536, 3)] 0, attempt 1540 0 1540 0 [(1565, 1), (1536, 3)] 0, attempt 1541 0 1541 0 [(1566, 1), (1536, 3)] 0, attempt 1542 0 1542 0 [(1567, 1), (1536, 3)] 0, attempt 1543 0 1543 0 [(1568, 1), (1536, 3)] 0, attempt 1544 0 1544 0 [(1569, 1), (1536, 3)] 0, attempt 1545 0 1545 0 [(1570, 1), (1536, 3)] 0, attempt 1546 0 1546 0 [(1571, 1), (1536, 3)] 0, attempt 1547 0 1547 0 [(1572, 1), (1536, 3)] 0, attempt 1548 0 1548 0 [(1573, 1), (1536, 3)] 0, attempt 1549 0 1549 0 [(1574, 1), (1536, 3)] 0, attempt 1550 0 1550 0 [(1575, 1), (1536, 3)] 0, attempt 1551 0 1551 0 [(1576, 1), (1536, 3)] 0, attempt 1552 0 1552 0 [(1577, 1), (1536, 3)] 0, attempt 1553 0 1553 0 [(1578, 1), (1536, 3)] 0, attempt 1554 0 1554 0 [(1579, 1), (1536, 3)] 0, attempt 1555 0 1555 0 [(1580, 1), (1536, 3)] 0, attempt 1556 0 1556 0 [(1581, 1), (1536, 3)] 0, attempt 1557 0 1557 0 [(1582, 1), (1536, 3)] 0, attempt 1558 0 1558 0 [(1583, 1), (1536, 3)] 0, attempt 1559 0 1559 0 [(1584, 1), (1536, 3)] 0, attempt 1560 0 1560 0 [(1585, 1), (1536, 3)] 0, attempt 1561 0 1561 0 [(1586, 1), (1536, 3)] 0, attempt 1562 0 1562 0 [(1587, 1), (1536, 3)] 0, attempt 1563 0 1563 0 [(1588, 1), (1536, 3)] 0, attempt 1564 0 1564 0 [(1589, 1), (1536, 3)] 0, attempt 1565 0 1565 0 [(1590, 1), (1536, 3)] 0, attempt 1566 0 1566 0 [(1591, 1), (1536, 3)] 0, attempt 1567 0 1567 0 [(1592, 1), (1536, 3)] 0]
def counters001 : List Nat := [1568, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk000_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1536
        counters000 chunk000 = true ∧ chunk000.length = 32 ∧
      advanceCsrCounters counters000 chunk000 = counters001 := by decide

def chunk001 : List CsrExecutableAttempt :=
  [attempt 1568 0 1568 0 [(1593, 1), (1536, 3)] 0, attempt 1569 0 1569 0 [(1594, 1), (1536, 3)] 0, attempt 1570 0 1570 0 [(1595, 1), (1536, 3)] 0, attempt 1571 0 1571 0 [(1596, 1), (1536, 3)] 0, attempt 1572 0 1572 0 [(1597, 1), (1536, 3)] 0, attempt 1573 0 1573 0 [(1598, 1), (1536, 3)] 0, attempt 1574 0 1574 0 [(1599, 1), (1536, 3)] 0, attempt 1575 0 1575 0 [(1601, 1), (1600, 3)] 0, attempt 1576 0 1576 0 [(1602, 1), (1600, 3)] 0, attempt 1577 0 1577 0 [(1603, 1), (1600, 3)] 0, attempt 1578 0 1578 0 [(1604, 1), (1600, 3)] 0, attempt 1579 0 1579 0 [(1605, 1), (1600, 3)] 0, attempt 1580 0 1580 0 [(1606, 1), (1600, 3)] 0, attempt 1581 0 1581 0 [(1607, 1), (1600, 3)] 0, attempt 1582 0 1582 0 [(1608, 1), (1600, 3)] 0, attempt 1583 0 1583 0 [(1609, 1), (1600, 3)] 0, attempt 1584 0 1584 0 [(1610, 1), (1600, 3)] 0, attempt 1585 0 1585 0 [(1611, 1), (1600, 3)] 0, attempt 1586 0 1586 0 [(1612, 1), (1600, 3)] 0, attempt 1587 0 1587 0 [(1613, 1), (1600, 3)] 0, attempt 1588 0 1588 0 [(1614, 1), (1600, 3)] 0, attempt 1589 0 1589 0 [(1615, 1), (1600, 3)] 0, attempt 1590 0 1590 0 [(1616, 1), (1600, 3)] 0, attempt 1591 0 1591 0 [(1617, 1), (1600, 3)] 0, attempt 1592 0 1592 0 [(1618, 1), (1600, 3)] 0, attempt 1593 0 1593 0 [(1619, 1), (1600, 3)] 0, attempt 1594 0 1594 0 [(1620, 1), (1600, 3)] 0, attempt 1595 0 1595 0 [(1621, 1), (1600, 3)] 0, attempt 1596 0 1596 0 [(1622, 1), (1600, 3)] 0, attempt 1597 0 1597 0 [(1623, 1), (1600, 3)] 0, attempt 1598 0 1598 0 [(1624, 1), (1600, 3)] 0, attempt 1599 0 1599 0 [(1625, 1), (1600, 3)] 0]
def counters002 : List Nat := [1600, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk001_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1568
        counters001 chunk001 = true ∧ chunk001.length = 32 ∧
      advanceCsrCounters counters001 chunk001 = counters002 := by decide

def chunk002 : List CsrExecutableAttempt :=
  [attempt 1600 0 1600 0 [(1626, 1), (1600, 3)] 0, attempt 1601 0 1601 0 [(1627, 1), (1600, 3)] 0, attempt 1602 0 1602 0 [(1628, 1), (1600, 3)] 0, attempt 1603 0 1603 0 [(1629, 1), (1600, 3)] 0, attempt 1604 0 1604 0 [(1630, 1), (1600, 3)] 0, attempt 1605 0 1605 0 [(1631, 1), (1600, 3)] 0, attempt 1606 0 1606 0 [(1632, 1), (1600, 3)] 0, attempt 1607 0 1607 0 [(1633, 1), (1600, 3)] 0, attempt 1608 0 1608 0 [(1634, 1), (1600, 3)] 0, attempt 1609 0 1609 0 [(1635, 1), (1600, 3)] 0, attempt 1610 0 1610 0 [(1636, 1), (1600, 3)] 0, attempt 1611 0 1611 0 [(1637, 1), (1600, 3)] 0, attempt 1612 0 1612 0 [(1638, 1), (1600, 3)] 0, attempt 1613 0 1613 0 [(1639, 1), (1600, 3)] 0, attempt 1614 0 1614 0 [(1640, 1), (1600, 3)] 0, attempt 1615 0 1615 0 [(1641, 1), (1600, 3)] 0, attempt 1616 0 1616 0 [(1642, 1), (1600, 3)] 0, attempt 1617 0 1617 0 [(1643, 1), (1600, 3)] 0, attempt 1618 0 1618 0 [(1644, 1), (1600, 3)] 0, attempt 1619 0 1619 0 [(1645, 1), (1600, 3)] 0, attempt 1620 0 1620 0 [(1646, 1), (1600, 3)] 0, attempt 1621 0 1621 0 [(1647, 1), (1600, 3)] 0, attempt 1622 0 1622 0 [(1648, 1), (1600, 3)] 0, attempt 1623 0 1623 0 [(1649, 1), (1600, 3)] 0, attempt 1624 0 1624 0 [(1650, 1), (1600, 3)] 0, attempt 1625 0 1625 0 [(1651, 1), (1600, 3)] 0, attempt 1626 0 1626 0 [(1652, 1), (1600, 3)] 0, attempt 1627 0 1627 0 [(1653, 1), (1600, 3)] 0, attempt 1628 0 1628 0 [(1654, 1), (1600, 3)] 0, attempt 1629 0 1629 0 [(1655, 1), (1600, 3)] 0, attempt 1630 0 1630 0 [(1656, 1), (1600, 3)] 0, attempt 1631 0 1631 0 [(1657, 1), (1600, 3)] 0]
def counters003 : List Nat := [1632, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk002_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1600
        counters002 chunk002 = true ∧ chunk002.length = 32 ∧
      advanceCsrCounters counters002 chunk002 = counters003 := by decide

def chunk003 : List CsrExecutableAttempt :=
  [attempt 1632 0 1632 0 [(1658, 1), (1600, 3)] 0, attempt 1633 0 1633 0 [(1659, 1), (1600, 3)] 0, attempt 1634 0 1634 0 [(1660, 1), (1600, 3)] 0, attempt 1635 0 1635 0 [(1661, 1), (1600, 3)] 0, attempt 1636 0 1636 0 [(1662, 1), (1600, 3)] 0, attempt 1637 0 1637 0 [(1663, 1), (1600, 3)] 0, attempt 1638 0 1638 0 [(1665, 1), (1664, 3)] 0, attempt 1639 0 1639 0 [(1666, 1), (1664, 3)] 0, attempt 1640 0 1640 0 [(1667, 1), (1664, 3)] 0, attempt 1641 0 1641 0 [(1668, 1), (1664, 3)] 0, attempt 1642 0 1642 0 [(1669, 1), (1664, 3)] 0, attempt 1643 0 1643 0 [(1670, 1), (1664, 3)] 0, attempt 1644 0 1644 0 [(1671, 1), (1664, 3)] 0, attempt 1645 0 1645 0 [(1672, 1), (1664, 3)] 0, attempt 1646 0 1646 0 [(1673, 1), (1664, 3)] 0, attempt 1647 0 1647 0 [(1674, 1), (1664, 3)] 0, attempt 1648 0 1648 0 [(1675, 1), (1664, 3)] 0, attempt 1649 0 1649 0 [(1676, 1), (1664, 3)] 0, attempt 1650 0 1650 0 [(1677, 1), (1664, 3)] 0, attempt 1651 0 1651 0 [(1678, 1), (1664, 3)] 0, attempt 1652 0 1652 0 [(1679, 1), (1664, 3)] 0, attempt 1653 0 1653 0 [(1680, 1), (1664, 3)] 0, attempt 1654 0 1654 0 [(1681, 1), (1664, 3)] 0, attempt 1655 0 1655 0 [(1682, 1), (1664, 3)] 0, attempt 1656 0 1656 0 [(1683, 1), (1664, 3)] 0, attempt 1657 0 1657 0 [(1684, 1), (1664, 3)] 0, attempt 1658 0 1658 0 [(1685, 1), (1664, 3)] 0, attempt 1659 0 1659 0 [(1686, 1), (1664, 3)] 0, attempt 1660 0 1660 0 [(1687, 1), (1664, 3)] 0, attempt 1661 0 1661 0 [(1688, 1), (1664, 3)] 0, attempt 1662 0 1662 0 [(1689, 1), (1664, 3)] 0, attempt 1663 0 1663 0 [(1690, 1), (1664, 3)] 0]
def counters004 : List Nat := [1664, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk003_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1632
        counters003 chunk003 = true ∧ chunk003.length = 32 ∧
      advanceCsrCounters counters003 chunk003 = counters004 := by decide

def chunk004 : List CsrExecutableAttempt :=
  [attempt 1664 0 1664 0 [(1691, 1), (1664, 3)] 0, attempt 1665 0 1665 0 [(1692, 1), (1664, 3)] 0, attempt 1666 0 1666 0 [(1693, 1), (1664, 3)] 0, attempt 1667 0 1667 0 [(1694, 1), (1664, 3)] 0, attempt 1668 0 1668 0 [(1695, 1), (1664, 3)] 0, attempt 1669 0 1669 0 [(1696, 1), (1664, 3)] 0, attempt 1670 0 1670 0 [(1697, 1), (1664, 3)] 0, attempt 1671 0 1671 0 [(1698, 1), (1664, 3)] 0, attempt 1672 0 1672 0 [(1699, 1), (1664, 3)] 0, attempt 1673 0 1673 0 [(1700, 1), (1664, 3)] 0, attempt 1674 0 1674 0 [(1701, 1), (1664, 3)] 0, attempt 1675 0 1675 0 [(1702, 1), (1664, 3)] 0, attempt 1676 0 1676 0 [(1703, 1), (1664, 3)] 0, attempt 1677 0 1677 0 [(1704, 1), (1664, 3)] 0, attempt 1678 0 1678 0 [(1705, 1), (1664, 3)] 0, attempt 1679 0 1679 0 [(1706, 1), (1664, 3)] 0, attempt 1680 0 1680 0 [(1707, 1), (1664, 3)] 0, attempt 1681 0 1681 0 [(1708, 1), (1664, 3)] 0, attempt 1682 0 1682 0 [(1709, 1), (1664, 3)] 0, attempt 1683 0 1683 0 [(1710, 1), (1664, 3)] 0, attempt 1684 0 1684 0 [(1711, 1), (1664, 3)] 0, attempt 1685 0 1685 0 [(1712, 1), (1664, 3)] 0, attempt 1686 0 1686 0 [(1713, 1), (1664, 3)] 0, attempt 1687 0 1687 0 [(1714, 1), (1664, 3)] 0, attempt 1688 0 1688 0 [(1715, 1), (1664, 3)] 0, attempt 1689 0 1689 0 [(1716, 1), (1664, 3)] 0, attempt 1690 0 1690 0 [(1717, 1), (1664, 3)] 0, attempt 1691 0 1691 0 [(1718, 1), (1664, 3)] 0, attempt 1692 0 1692 0 [(1719, 1), (1664, 3)] 0, attempt 1693 0 1693 0 [(1720, 1), (1664, 3)] 0, attempt 1694 0 1694 0 [(1721, 1), (1664, 3)] 0, attempt 1695 0 1695 0 [(1722, 1), (1664, 3)] 0]
def counters005 : List Nat := [1696, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk004_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1664
        counters004 chunk004 = true ∧ chunk004.length = 32 ∧
      advanceCsrCounters counters004 chunk004 = counters005 := by decide

def chunk005 : List CsrExecutableAttempt :=
  [attempt 1696 0 1696 0 [(1723, 1), (1664, 3)] 0, attempt 1697 0 1697 0 [(1724, 1), (1664, 3)] 0, attempt 1698 0 1698 0 [(1725, 1), (1664, 3)] 0, attempt 1699 0 1699 0 [(1726, 1), (1664, 3)] 0, attempt 1700 0 1700 0 [(1727, 1), (1664, 3)] 0, attempt 1701 0 1701 0 [(1729, 1), (1728, 3)] 0, attempt 1702 0 1702 0 [(1730, 1), (1728, 3)] 0, attempt 1703 0 1703 0 [(1731, 1), (1728, 3)] 0, attempt 1704 0 1704 0 [(1732, 1), (1728, 3)] 0, attempt 1705 0 1705 0 [(1733, 1), (1728, 3)] 0, attempt 1706 0 1706 0 [(1734, 1), (1728, 3)] 0, attempt 1707 0 1707 0 [(1735, 1), (1728, 3)] 0, attempt 1708 0 1708 0 [(1736, 1), (1728, 3)] 0, attempt 1709 0 1709 0 [(1737, 1), (1728, 3)] 0, attempt 1710 0 1710 0 [(1738, 1), (1728, 3)] 0, attempt 1711 0 1711 0 [(1739, 1), (1728, 3)] 0, attempt 1712 0 1712 0 [(1740, 1), (1728, 3)] 0, attempt 1713 0 1713 0 [(1741, 1), (1728, 3)] 0, attempt 1714 0 1714 0 [(1742, 1), (1728, 3)] 0, attempt 1715 0 1715 0 [(1743, 1), (1728, 3)] 0, attempt 1716 0 1716 0 [(1744, 1), (1728, 3)] 0, attempt 1717 0 1717 0 [(1745, 1), (1728, 3)] 0, attempt 1718 0 1718 0 [(1746, 1), (1728, 3)] 0, attempt 1719 0 1719 0 [(1747, 1), (1728, 3)] 0, attempt 1720 0 1720 0 [(1748, 1), (1728, 3)] 0, attempt 1721 0 1721 0 [(1749, 1), (1728, 3)] 0, attempt 1722 0 1722 0 [(1750, 1), (1728, 3)] 0, attempt 1723 0 1723 0 [(1751, 1), (1728, 3)] 0, attempt 1724 0 1724 0 [(1752, 1), (1728, 3)] 0, attempt 1725 0 1725 0 [(1753, 1), (1728, 3)] 0, attempt 1726 0 1726 0 [(1754, 1), (1728, 3)] 0, attempt 1727 0 1727 0 [(1755, 1), (1728, 3)] 0]
def counters006 : List Nat := [1728, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk005_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1696
        counters005 chunk005 = true ∧ chunk005.length = 32 ∧
      advanceCsrCounters counters005 chunk005 = counters006 := by decide

def chunk006 : List CsrExecutableAttempt :=
  [attempt 1728 0 1728 0 [(1756, 1), (1728, 3)] 0, attempt 1729 0 1729 0 [(1757, 1), (1728, 3)] 0, attempt 1730 0 1730 0 [(1758, 1), (1728, 3)] 0, attempt 1731 0 1731 0 [(1759, 1), (1728, 3)] 0, attempt 1732 0 1732 0 [(1760, 1), (1728, 3)] 0, attempt 1733 0 1733 0 [(1761, 1), (1728, 3)] 0, attempt 1734 0 1734 0 [(1762, 1), (1728, 3)] 0, attempt 1735 0 1735 0 [(1763, 1), (1728, 3)] 0, attempt 1736 0 1736 0 [(1764, 1), (1728, 3)] 0, attempt 1737 0 1737 0 [(1765, 1), (1728, 3)] 0, attempt 1738 0 1738 0 [(1766, 1), (1728, 3)] 0, attempt 1739 0 1739 0 [(1767, 1), (1728, 3)] 0, attempt 1740 0 1740 0 [(1768, 1), (1728, 3)] 0, attempt 1741 0 1741 0 [(1769, 1), (1728, 3)] 0, attempt 1742 0 1742 0 [(1770, 1), (1728, 3)] 0, attempt 1743 0 1743 0 [(1771, 1), (1728, 3)] 0, attempt 1744 0 1744 0 [(1772, 1), (1728, 3)] 0, attempt 1745 0 1745 0 [(1773, 1), (1728, 3)] 0, attempt 1746 0 1746 0 [(1774, 1), (1728, 3)] 0, attempt 1747 0 1747 0 [(1775, 1), (1728, 3)] 0, attempt 1748 0 1748 0 [(1776, 1), (1728, 3)] 0, attempt 1749 0 1749 0 [(1777, 1), (1728, 3)] 0, attempt 1750 0 1750 0 [(1778, 1), (1728, 3)] 0, attempt 1751 0 1751 0 [(1779, 1), (1728, 3)] 0, attempt 1752 0 1752 0 [(1780, 1), (1728, 3)] 0, attempt 1753 0 1753 0 [(1781, 1), (1728, 3)] 0, attempt 1754 0 1754 0 [(1782, 1), (1728, 3)] 0, attempt 1755 0 1755 0 [(1783, 1), (1728, 3)] 0, attempt 1756 0 1756 0 [(1784, 1), (1728, 3)] 0, attempt 1757 0 1757 0 [(1785, 1), (1728, 3)] 0, attempt 1758 0 1758 0 [(1786, 1), (1728, 3)] 0, attempt 1759 0 1759 0 [(1787, 1), (1728, 3)] 0]
def counters007 : List Nat := [1760, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk006_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1728
        counters006 chunk006 = true ∧ chunk006.length = 32 ∧
      advanceCsrCounters counters006 chunk006 = counters007 := by decide

def chunk007 : List CsrExecutableAttempt :=
  [attempt 1760 0 1760 0 [(1788, 1), (1728, 3)] 0, attempt 1761 0 1761 0 [(1789, 1), (1728, 3)] 0, attempt 1762 0 1762 0 [(1790, 1), (1728, 3)] 0, attempt 1763 0 1763 0 [(1791, 1), (1728, 3)] 0, attempt 1764 0 1764 0 [(1793, 1), (1792, 3)] 0, attempt 1765 0 1765 0 [(1794, 1), (1792, 3)] 0, attempt 1766 0 1766 0 [(1795, 1), (1792, 3)] 0, attempt 1767 0 1767 0 [(1796, 1), (1792, 3)] 0, attempt 1768 0 1768 0 [(1797, 1), (1792, 3)] 0, attempt 1769 0 1769 0 [(1798, 1), (1792, 3)] 0, attempt 1770 0 1770 0 [(1799, 1), (1792, 3)] 0, attempt 1771 0 1771 0 [(1800, 1), (1792, 3)] 0, attempt 1772 0 1772 0 [(1801, 1), (1792, 3)] 0, attempt 1773 0 1773 0 [(1802, 1), (1792, 3)] 0, attempt 1774 0 1774 0 [(1803, 1), (1792, 3)] 0, attempt 1775 0 1775 0 [(1804, 1), (1792, 3)] 0, attempt 1776 0 1776 0 [(1805, 1), (1792, 3)] 0, attempt 1777 0 1777 0 [(1806, 1), (1792, 3)] 0, attempt 1778 0 1778 0 [(1807, 1), (1792, 3)] 0, attempt 1779 0 1779 0 [(1808, 1), (1792, 3)] 0, attempt 1780 0 1780 0 [(1809, 1), (1792, 3)] 0, attempt 1781 0 1781 0 [(1810, 1), (1792, 3)] 0, attempt 1782 0 1782 0 [(1811, 1), (1792, 3)] 0, attempt 1783 0 1783 0 [(1812, 1), (1792, 3)] 0, attempt 1784 0 1784 0 [(1813, 1), (1792, 3)] 0, attempt 1785 0 1785 0 [(1814, 1), (1792, 3)] 0, attempt 1786 0 1786 0 [(1815, 1), (1792, 3)] 0, attempt 1787 0 1787 0 [(1816, 1), (1792, 3)] 0, attempt 1788 0 1788 0 [(1817, 1), (1792, 3)] 0, attempt 1789 0 1789 0 [(1818, 1), (1792, 3)] 0, attempt 1790 0 1790 0 [(1819, 1), (1792, 3)] 0, attempt 1791 0 1791 0 [(1820, 1), (1792, 3)] 0]
def counters008 : List Nat := [1792, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk007_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1760
        counters007 chunk007 = true ∧ chunk007.length = 32 ∧
      advanceCsrCounters counters007 chunk007 = counters008 := by decide

def chunk008 : List CsrExecutableAttempt :=
  [attempt 1792 0 1792 0 [(1821, 1), (1792, 3)] 0, attempt 1793 0 1793 0 [(1822, 1), (1792, 3)] 0, attempt 1794 0 1794 0 [(1823, 1), (1792, 3)] 0, attempt 1795 0 1795 0 [(1824, 1), (1792, 3)] 0, attempt 1796 0 1796 0 [(1825, 1), (1792, 3)] 0, attempt 1797 0 1797 0 [(1826, 1), (1792, 3)] 0, attempt 1798 0 1798 0 [(1827, 1), (1792, 3)] 0, attempt 1799 0 1799 0 [(1828, 1), (1792, 3)] 0, attempt 1800 0 1800 0 [(1829, 1), (1792, 3)] 0, attempt 1801 0 1801 0 [(1830, 1), (1792, 3)] 0, attempt 1802 0 1802 0 [(1831, 1), (1792, 3)] 0, attempt 1803 0 1803 0 [(1832, 1), (1792, 3)] 0, attempt 1804 0 1804 0 [(1833, 1), (1792, 3)] 0, attempt 1805 0 1805 0 [(1834, 1), (1792, 3)] 0, attempt 1806 0 1806 0 [(1835, 1), (1792, 3)] 0, attempt 1807 0 1807 0 [(1836, 1), (1792, 3)] 0, attempt 1808 0 1808 0 [(1837, 1), (1792, 3)] 0, attempt 1809 0 1809 0 [(1838, 1), (1792, 3)] 0, attempt 1810 0 1810 0 [(1839, 1), (1792, 3)] 0, attempt 1811 0 1811 0 [(1840, 1), (1792, 3)] 0, attempt 1812 0 1812 0 [(1841, 1), (1792, 3)] 0, attempt 1813 0 1813 0 [(1842, 1), (1792, 3)] 0, attempt 1814 0 1814 0 [(1843, 1), (1792, 3)] 0, attempt 1815 0 1815 0 [(1844, 1), (1792, 3)] 0, attempt 1816 0 1816 0 [(1845, 1), (1792, 3)] 0, attempt 1817 0 1817 0 [(1846, 1), (1792, 3)] 0, attempt 1818 0 1818 0 [(1847, 1), (1792, 3)] 0, attempt 1819 0 1819 0 [(1848, 1), (1792, 3)] 0, attempt 1820 0 1820 0 [(1849, 1), (1792, 3)] 0, attempt 1821 0 1821 0 [(1850, 1), (1792, 3)] 0, attempt 1822 0 1822 0 [(1851, 1), (1792, 3)] 0, attempt 1823 0 1823 0 [(1852, 1), (1792, 3)] 0]
def counters009 : List Nat := [1824, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk008_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1792
        counters008 chunk008 = true ∧ chunk008.length = 32 ∧
      advanceCsrCounters counters008 chunk008 = counters009 := by decide

def chunk009 : List CsrExecutableAttempt :=
  [attempt 1824 0 1824 0 [(1853, 1), (1792, 3)] 0, attempt 1825 0 1825 0 [(1854, 1), (1792, 3)] 0, attempt 1826 0 1826 0 [(1855, 1), (1792, 3)] 0, attempt 1827 0 1827 0 [(1857, 1), (1856, 3)] 0, attempt 1828 0 1828 0 [(1858, 1), (1856, 3)] 0, attempt 1829 0 1829 0 [(1859, 1), (1856, 3)] 0, attempt 1830 0 1830 0 [(1860, 1), (1856, 3)] 0, attempt 1831 0 1831 0 [(1861, 1), (1856, 3)] 0, attempt 1832 0 1832 0 [(1862, 1), (1856, 3)] 0, attempt 1833 0 1833 0 [(1863, 1), (1856, 3)] 0, attempt 1834 0 1834 0 [(1864, 1), (1856, 3)] 0, attempt 1835 0 1835 0 [(1865, 1), (1856, 3)] 0, attempt 1836 0 1836 0 [(1866, 1), (1856, 3)] 0, attempt 1837 0 1837 0 [(1867, 1), (1856, 3)] 0, attempt 1838 0 1838 0 [(1868, 1), (1856, 3)] 0, attempt 1839 0 1839 0 [(1869, 1), (1856, 3)] 0, attempt 1840 0 1840 0 [(1870, 1), (1856, 3)] 0, attempt 1841 0 1841 0 [(1871, 1), (1856, 3)] 0, attempt 1842 0 1842 0 [(1872, 1), (1856, 3)] 0, attempt 1843 0 1843 0 [(1873, 1), (1856, 3)] 0, attempt 1844 0 1844 0 [(1874, 1), (1856, 3)] 0, attempt 1845 0 1845 0 [(1875, 1), (1856, 3)] 0, attempt 1846 0 1846 0 [(1876, 1), (1856, 3)] 0, attempt 1847 0 1847 0 [(1877, 1), (1856, 3)] 0, attempt 1848 0 1848 0 [(1878, 1), (1856, 3)] 0, attempt 1849 0 1849 0 [(1879, 1), (1856, 3)] 0, attempt 1850 0 1850 0 [(1880, 1), (1856, 3)] 0, attempt 1851 0 1851 0 [(1881, 1), (1856, 3)] 0, attempt 1852 0 1852 0 [(1882, 1), (1856, 3)] 0, attempt 1853 0 1853 0 [(1883, 1), (1856, 3)] 0, attempt 1854 0 1854 0 [(1884, 1), (1856, 3)] 0, attempt 1855 0 1855 0 [(1885, 1), (1856, 3)] 0]
def counters010 : List Nat := [1856, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk009_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1824
        counters009 chunk009 = true ∧ chunk009.length = 32 ∧
      advanceCsrCounters counters009 chunk009 = counters010 := by decide

def chunk010 : List CsrExecutableAttempt :=
  [attempt 1856 0 1856 0 [(1886, 1), (1856, 3)] 0, attempt 1857 0 1857 0 [(1887, 1), (1856, 3)] 0, attempt 1858 0 1858 0 [(1888, 1), (1856, 3)] 0, attempt 1859 0 1859 0 [(1889, 1), (1856, 3)] 0, attempt 1860 0 1860 0 [(1890, 1), (1856, 3)] 0, attempt 1861 0 1861 0 [(1891, 1), (1856, 3)] 0, attempt 1862 0 1862 0 [(1892, 1), (1856, 3)] 0, attempt 1863 0 1863 0 [(1893, 1), (1856, 3)] 0, attempt 1864 0 1864 0 [(1894, 1), (1856, 3)] 0, attempt 1865 0 1865 0 [(1895, 1), (1856, 3)] 0, attempt 1866 0 1866 0 [(1896, 1), (1856, 3)] 0, attempt 1867 0 1867 0 [(1897, 1), (1856, 3)] 0, attempt 1868 0 1868 0 [(1898, 1), (1856, 3)] 0, attempt 1869 0 1869 0 [(1899, 1), (1856, 3)] 0, attempt 1870 0 1870 0 [(1900, 1), (1856, 3)] 0, attempt 1871 0 1871 0 [(1901, 1), (1856, 3)] 0, attempt 1872 0 1872 0 [(1902, 1), (1856, 3)] 0, attempt 1873 0 1873 0 [(1903, 1), (1856, 3)] 0, attempt 1874 0 1874 0 [(1904, 1), (1856, 3)] 0, attempt 1875 0 1875 0 [(1905, 1), (1856, 3)] 0, attempt 1876 0 1876 0 [(1906, 1), (1856, 3)] 0, attempt 1877 0 1877 0 [(1907, 1), (1856, 3)] 0, attempt 1878 0 1878 0 [(1908, 1), (1856, 3)] 0, attempt 1879 0 1879 0 [(1909, 1), (1856, 3)] 0, attempt 1880 0 1880 0 [(1910, 1), (1856, 3)] 0, attempt 1881 0 1881 0 [(1911, 1), (1856, 3)] 0, attempt 1882 0 1882 0 [(1912, 1), (1856, 3)] 0, attempt 1883 0 1883 0 [(1913, 1), (1856, 3)] 0, attempt 1884 0 1884 0 [(1914, 1), (1856, 3)] 0, attempt 1885 0 1885 0 [(1915, 1), (1856, 3)] 0, attempt 1886 0 1886 0 [(1916, 1), (1856, 3)] 0, attempt 1887 0 1887 0 [(1917, 1), (1856, 3)] 0]
def counters011 : List Nat := [1888, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk010_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1856
        counters010 chunk010 = true ∧ chunk010.length = 32 ∧
      advanceCsrCounters counters010 chunk010 = counters011 := by decide

def chunk011 : List CsrExecutableAttempt :=
  [attempt 1888 0 1888 0 [(1918, 1), (1856, 3)] 0, attempt 1889 0 1889 0 [(1919, 1), (1856, 3)] 0, attempt 1890 0 1890 0 [(1921, 1), (1920, 3)] 0, attempt 1891 0 1891 0 [(1922, 1), (1920, 3)] 0, attempt 1892 0 1892 0 [(1923, 1), (1920, 3)] 0, attempt 1893 0 1893 0 [(1924, 1), (1920, 3)] 0, attempt 1894 0 1894 0 [(1925, 1), (1920, 3)] 0, attempt 1895 0 1895 0 [(1926, 1), (1920, 3)] 0, attempt 1896 0 1896 0 [(1927, 1), (1920, 3)] 0, attempt 1897 0 1897 0 [(1928, 1), (1920, 3)] 0, attempt 1898 0 1898 0 [(1929, 1), (1920, 3)] 0, attempt 1899 0 1899 0 [(1930, 1), (1920, 3)] 0, attempt 1900 0 1900 0 [(1931, 1), (1920, 3)] 0, attempt 1901 0 1901 0 [(1932, 1), (1920, 3)] 0, attempt 1902 0 1902 0 [(1933, 1), (1920, 3)] 0, attempt 1903 0 1903 0 [(1934, 1), (1920, 3)] 0, attempt 1904 0 1904 0 [(1935, 1), (1920, 3)] 0, attempt 1905 0 1905 0 [(1936, 1), (1920, 3)] 0, attempt 1906 0 1906 0 [(1937, 1), (1920, 3)] 0, attempt 1907 0 1907 0 [(1938, 1), (1920, 3)] 0, attempt 1908 0 1908 0 [(1939, 1), (1920, 3)] 0, attempt 1909 0 1909 0 [(1940, 1), (1920, 3)] 0, attempt 1910 0 1910 0 [(1941, 1), (1920, 3)] 0, attempt 1911 0 1911 0 [(1942, 1), (1920, 3)] 0, attempt 1912 0 1912 0 [(1943, 1), (1920, 3)] 0, attempt 1913 0 1913 0 [(1944, 1), (1920, 3)] 0, attempt 1914 0 1914 0 [(1945, 1), (1920, 3)] 0, attempt 1915 0 1915 0 [(1946, 1), (1920, 3)] 0, attempt 1916 0 1916 0 [(1947, 1), (1920, 3)] 0, attempt 1917 0 1917 0 [(1948, 1), (1920, 3)] 0, attempt 1918 0 1918 0 [(1949, 1), (1920, 3)] 0, attempt 1919 0 1919 0 [(1950, 1), (1920, 3)] 0]
def counters012 : List Nat := [1920, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk011_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1888
        counters011 chunk011 = true ∧ chunk011.length = 32 ∧
      advanceCsrCounters counters011 chunk011 = counters012 := by decide

def chunk012 : List CsrExecutableAttempt :=
  [attempt 1920 0 1920 0 [(1951, 1), (1920, 3)] 0, attempt 1921 0 1921 0 [(1952, 1), (1920, 3)] 0, attempt 1922 0 1922 0 [(1953, 1), (1920, 3)] 0, attempt 1923 0 1923 0 [(1954, 1), (1920, 3)] 0, attempt 1924 0 1924 0 [(1955, 1), (1920, 3)] 0, attempt 1925 0 1925 0 [(1956, 1), (1920, 3)] 0, attempt 1926 0 1926 0 [(1957, 1), (1920, 3)] 0, attempt 1927 0 1927 0 [(1958, 1), (1920, 3)] 0, attempt 1928 0 1928 0 [(1959, 1), (1920, 3)] 0, attempt 1929 0 1929 0 [(1960, 1), (1920, 3)] 0, attempt 1930 0 1930 0 [(1961, 1), (1920, 3)] 0, attempt 1931 0 1931 0 [(1962, 1), (1920, 3)] 0, attempt 1932 0 1932 0 [(1963, 1), (1920, 3)] 0, attempt 1933 0 1933 0 [(1964, 1), (1920, 3)] 0, attempt 1934 0 1934 0 [(1965, 1), (1920, 3)] 0, attempt 1935 0 1935 0 [(1966, 1), (1920, 3)] 0, attempt 1936 0 1936 0 [(1967, 1), (1920, 3)] 0, attempt 1937 0 1937 0 [(1968, 1), (1920, 3)] 0, attempt 1938 0 1938 0 [(1969, 1), (1920, 3)] 0, attempt 1939 0 1939 0 [(1970, 1), (1920, 3)] 0, attempt 1940 0 1940 0 [(1971, 1), (1920, 3)] 0, attempt 1941 0 1941 0 [(1972, 1), (1920, 3)] 0, attempt 1942 0 1942 0 [(1973, 1), (1920, 3)] 0, attempt 1943 0 1943 0 [(1974, 1), (1920, 3)] 0, attempt 1944 0 1944 0 [(1975, 1), (1920, 3)] 0, attempt 1945 0 1945 0 [(1976, 1), (1920, 3)] 0, attempt 1946 0 1946 0 [(1977, 1), (1920, 3)] 0, attempt 1947 0 1947 0 [(1978, 1), (1920, 3)] 0, attempt 1948 0 1948 0 [(1979, 1), (1920, 3)] 0, attempt 1949 0 1949 0 [(1980, 1), (1920, 3)] 0, attempt 1950 0 1950 0 [(1981, 1), (1920, 3)] 0, attempt 1951 0 1951 0 [(1982, 1), (1920, 3)] 0]
def counters013 : List Nat := [1952, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk012_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1920
        counters012 chunk012 = true ∧ chunk012.length = 32 ∧
      advanceCsrCounters counters012 chunk012 = counters013 := by decide

def chunk013 : List CsrExecutableAttempt :=
  [attempt 1952 0 1952 0 [(1983, 1), (1920, 3)] 0, attempt 1953 0 1953 0 [(1985, 1), (1984, 3)] 0, attempt 1954 0 1954 0 [(1986, 1), (1984, 3)] 0, attempt 1955 0 1955 0 [(1987, 1), (1984, 3)] 0, attempt 1956 0 1956 0 [(1988, 1), (1984, 3)] 0, attempt 1957 0 1957 0 [(1989, 1), (1984, 3)] 0, attempt 1958 0 1958 0 [(1990, 1), (1984, 3)] 0, attempt 1959 0 1959 0 [(1991, 1), (1984, 3)] 0, attempt 1960 0 1960 0 [(1992, 1), (1984, 3)] 0, attempt 1961 0 1961 0 [(1993, 1), (1984, 3)] 0, attempt 1962 0 1962 0 [(1994, 1), (1984, 3)] 0, attempt 1963 0 1963 0 [(1995, 1), (1984, 3)] 0, attempt 1964 0 1964 0 [(1996, 1), (1984, 3)] 0, attempt 1965 0 1965 0 [(1997, 1), (1984, 3)] 0, attempt 1966 0 1966 0 [(1998, 1), (1984, 3)] 0, attempt 1967 0 1967 0 [(1999, 1), (1984, 3)] 0, attempt 1968 0 1968 0 [(2000, 1), (1984, 3)] 0, attempt 1969 0 1969 0 [(2001, 1), (1984, 3)] 0, attempt 1970 0 1970 0 [(2002, 1), (1984, 3)] 0, attempt 1971 0 1971 0 [(2003, 1), (1984, 3)] 0, attempt 1972 0 1972 0 [(2004, 1), (1984, 3)] 0, attempt 1973 0 1973 0 [(2005, 1), (1984, 3)] 0, attempt 1974 0 1974 0 [(2006, 1), (1984, 3)] 0, attempt 1975 0 1975 0 [(2007, 1), (1984, 3)] 0, attempt 1976 0 1976 0 [(2008, 1), (1984, 3)] 0, attempt 1977 0 1977 0 [(2009, 1), (1984, 3)] 0, attempt 1978 0 1978 0 [(2010, 1), (1984, 3)] 0, attempt 1979 0 1979 0 [(2011, 1), (1984, 3)] 0, attempt 1980 0 1980 0 [(2012, 1), (1984, 3)] 0, attempt 1981 0 1981 0 [(2013, 1), (1984, 3)] 0, attempt 1982 0 1982 0 [(2014, 1), (1984, 3)] 0, attempt 1983 0 1983 0 [(2015, 1), (1984, 3)] 0]
def counters014 : List Nat := [1984, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk013_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1952
        counters013 chunk013 = true ∧ chunk013.length = 32 ∧
      advanceCsrCounters counters013 chunk013 = counters014 := by decide

def chunk014 : List CsrExecutableAttempt :=
  [attempt 1984 0 1984 0 [(2016, 1), (1984, 3)] 0, attempt 1985 0 1985 0 [(2017, 1), (1984, 3)] 0, attempt 1986 0 1986 0 [(2018, 1), (1984, 3)] 0, attempt 1987 0 1987 0 [(2019, 1), (1984, 3)] 0, attempt 1988 0 1988 0 [(2020, 1), (1984, 3)] 0, attempt 1989 0 1989 0 [(2021, 1), (1984, 3)] 0, attempt 1990 0 1990 0 [(2022, 1), (1984, 3)] 0, attempt 1991 0 1991 0 [(2023, 1), (1984, 3)] 0, attempt 1992 0 1992 0 [(2024, 1), (1984, 3)] 0, attempt 1993 0 1993 0 [(2025, 1), (1984, 3)] 0, attempt 1994 0 1994 0 [(2026, 1), (1984, 3)] 0, attempt 1995 0 1995 0 [(2027, 1), (1984, 3)] 0, attempt 1996 0 1996 0 [(2028, 1), (1984, 3)] 0, attempt 1997 0 1997 0 [(2029, 1), (1984, 3)] 0, attempt 1998 0 1998 0 [(2030, 1), (1984, 3)] 0, attempt 1999 0 1999 0 [(2031, 1), (1984, 3)] 0, attempt 2000 0 2000 0 [(2032, 1), (1984, 3)] 0, attempt 2001 0 2001 0 [(2033, 1), (1984, 3)] 0, attempt 2002 0 2002 0 [(2034, 1), (1984, 3)] 0, attempt 2003 0 2003 0 [(2035, 1), (1984, 3)] 0, attempt 2004 0 2004 0 [(2036, 1), (1984, 3)] 0, attempt 2005 0 2005 0 [(2037, 1), (1984, 3)] 0, attempt 2006 0 2006 0 [(2038, 1), (1984, 3)] 0, attempt 2007 0 2007 0 [(2039, 1), (1984, 3)] 0, attempt 2008 0 2008 0 [(2040, 1), (1984, 3)] 0, attempt 2009 0 2009 0 [(2041, 1), (1984, 3)] 0, attempt 2010 0 2010 0 [(2042, 1), (1984, 3)] 0, attempt 2011 0 2011 0 [(2043, 1), (1984, 3)] 0, attempt 2012 0 2012 0 [(2044, 1), (1984, 3)] 0, attempt 2013 0 2013 0 [(2045, 1), (1984, 3)] 0, attempt 2014 0 2014 0 [(2046, 1), (1984, 3)] 0, attempt 2015 0 2015 0 [(2047, 1), (1984, 3)] 0]
def counters015 : List Nat := [2016, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk014_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1984
        counters014 chunk014 = true ∧ chunk014.length = 32 ∧
      advanceCsrCounters counters014 chunk014 = counters015 := by decide

def chunk015 : List CsrExecutableAttempt :=
  [attempt 2016 0 2016 0 [(2049, 1), (2048, 3)] 0, attempt 2017 0 2017 0 [(2050, 1), (2048, 3)] 0, attempt 2018 0 2018 0 [(2051, 1), (2048, 3)] 0, attempt 2019 0 2019 0 [(2052, 1), (2048, 3)] 0, attempt 2020 0 2020 0 [(2053, 1), (2048, 3)] 0, attempt 2021 0 2021 0 [(2054, 1), (2048, 3)] 0, attempt 2022 0 2022 0 [(2055, 1), (2048, 3)] 0, attempt 2023 0 2023 0 [(2056, 1), (2048, 3)] 0, attempt 2024 0 2024 0 [(2057, 1), (2048, 3)] 0, attempt 2025 0 2025 0 [(2058, 1), (2048, 3)] 0, attempt 2026 0 2026 0 [(2059, 1), (2048, 3)] 0, attempt 2027 0 2027 0 [(2060, 1), (2048, 3)] 0, attempt 2028 0 2028 0 [(2061, 1), (2048, 3)] 0, attempt 2029 0 2029 0 [(2062, 1), (2048, 3)] 0, attempt 2030 0 2030 0 [(2063, 1), (2048, 3)] 0, attempt 2031 0 2031 0 [(2064, 1), (2048, 3)] 0, attempt 2032 0 2032 0 [(2065, 1), (2048, 3)] 0, attempt 2033 0 2033 0 [(2066, 1), (2048, 3)] 0, attempt 2034 0 2034 0 [(2067, 1), (2048, 3)] 0, attempt 2035 0 2035 0 [(2068, 1), (2048, 3)] 0, attempt 2036 0 2036 0 [(2069, 1), (2048, 3)] 0, attempt 2037 0 2037 0 [(2070, 1), (2048, 3)] 0, attempt 2038 0 2038 0 [(2071, 1), (2048, 3)] 0, attempt 2039 0 2039 0 [(2072, 1), (2048, 3)] 0, attempt 2040 0 2040 0 [(2073, 1), (2048, 3)] 0, attempt 2041 0 2041 0 [(2074, 1), (2048, 3)] 0, attempt 2042 0 2042 0 [(2075, 1), (2048, 3)] 0, attempt 2043 0 2043 0 [(2076, 1), (2048, 3)] 0, attempt 2044 0 2044 0 [(2077, 1), (2048, 3)] 0, attempt 2045 0 2045 0 [(2078, 1), (2048, 3)] 0, attempt 2046 0 2046 0 [(2079, 1), (2048, 3)] 0, attempt 2047 0 2047 0 [(2080, 1), (2048, 3)] 0]
def counters016 : List Nat := [2048, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
theorem chunk015_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2016
        counters015 chunk015 = true ∧ chunk015.length = 32 ∧
      advanceCsrCounters counters015 chunk015 = counters016 := by decide

def suffix016 : List CsrExecutableAttempt := []
theorem suffix016_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2048
      counters016 suffix016 = true := by rfl
theorem suffix016_length : suffix016.length = 0 := by rfl
theorem suffix016_state : advanceCsrCounters counters016 suffix016 = counters016 := by rfl

def suffix015 : List CsrExecutableAttempt := chunk015 ++ suffix016
theorem suffix015_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 2016
      counters015 suffix015 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk015 suffix016 2016 2048 counters015 counters016
    chunk015_checked.1 (congrArg (Nat.add 2016) chunk015_checked.2.1)
    chunk015_checked.2.2 suffix016_checked
theorem suffix015_length : suffix015.length = 32 := by
  rw [suffix015, List.length_append, chunk015_checked.2.1, suffix016_length]
theorem suffix015_state : advanceCsrCounters counters015 suffix015 = counters016 := by
  rw [suffix015, advanceCsrCounters_append, chunk015_checked.2.2, suffix016_state]

def suffix014 : List CsrExecutableAttempt := chunk014 ++ suffix015
theorem suffix014_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1984
      counters014 suffix014 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk014 suffix015 1984 2016 counters014 counters015
    chunk014_checked.1 (congrArg (Nat.add 1984) chunk014_checked.2.1)
    chunk014_checked.2.2 suffix015_checked
theorem suffix014_length : suffix014.length = 64 := by
  rw [suffix014, List.length_append, chunk014_checked.2.1, suffix015_length]
theorem suffix014_state : advanceCsrCounters counters014 suffix014 = counters016 := by
  rw [suffix014, advanceCsrCounters_append, chunk014_checked.2.2, suffix015_state]

def suffix013 : List CsrExecutableAttempt := chunk013 ++ suffix014
theorem suffix013_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1952
      counters013 suffix013 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk013 suffix014 1952 1984 counters013 counters014
    chunk013_checked.1 (congrArg (Nat.add 1952) chunk013_checked.2.1)
    chunk013_checked.2.2 suffix014_checked
theorem suffix013_length : suffix013.length = 96 := by
  rw [suffix013, List.length_append, chunk013_checked.2.1, suffix014_length]
theorem suffix013_state : advanceCsrCounters counters013 suffix013 = counters016 := by
  rw [suffix013, advanceCsrCounters_append, chunk013_checked.2.2, suffix014_state]

def suffix012 : List CsrExecutableAttempt := chunk012 ++ suffix013
theorem suffix012_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1920
      counters012 suffix012 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk012 suffix013 1920 1952 counters012 counters013
    chunk012_checked.1 (congrArg (Nat.add 1920) chunk012_checked.2.1)
    chunk012_checked.2.2 suffix013_checked
theorem suffix012_length : suffix012.length = 128 := by
  rw [suffix012, List.length_append, chunk012_checked.2.1, suffix013_length]
theorem suffix012_state : advanceCsrCounters counters012 suffix012 = counters016 := by
  rw [suffix012, advanceCsrCounters_append, chunk012_checked.2.2, suffix013_state]

def suffix011 : List CsrExecutableAttempt := chunk011 ++ suffix012
theorem suffix011_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1888
      counters011 suffix011 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk011 suffix012 1888 1920 counters011 counters012
    chunk011_checked.1 (congrArg (Nat.add 1888) chunk011_checked.2.1)
    chunk011_checked.2.2 suffix012_checked
theorem suffix011_length : suffix011.length = 160 := by
  rw [suffix011, List.length_append, chunk011_checked.2.1, suffix012_length]
theorem suffix011_state : advanceCsrCounters counters011 suffix011 = counters016 := by
  rw [suffix011, advanceCsrCounters_append, chunk011_checked.2.2, suffix012_state]

def suffix010 : List CsrExecutableAttempt := chunk010 ++ suffix011
theorem suffix010_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1856
      counters010 suffix010 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk010 suffix011 1856 1888 counters010 counters011
    chunk010_checked.1 (congrArg (Nat.add 1856) chunk010_checked.2.1)
    chunk010_checked.2.2 suffix011_checked
theorem suffix010_length : suffix010.length = 192 := by
  rw [suffix010, List.length_append, chunk010_checked.2.1, suffix011_length]
theorem suffix010_state : advanceCsrCounters counters010 suffix010 = counters016 := by
  rw [suffix010, advanceCsrCounters_append, chunk010_checked.2.2, suffix011_state]

def suffix009 : List CsrExecutableAttempt := chunk009 ++ suffix010
theorem suffix009_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1824
      counters009 suffix009 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk009 suffix010 1824 1856 counters009 counters010
    chunk009_checked.1 (congrArg (Nat.add 1824) chunk009_checked.2.1)
    chunk009_checked.2.2 suffix010_checked
theorem suffix009_length : suffix009.length = 224 := by
  rw [suffix009, List.length_append, chunk009_checked.2.1, suffix010_length]
theorem suffix009_state : advanceCsrCounters counters009 suffix009 = counters016 := by
  rw [suffix009, advanceCsrCounters_append, chunk009_checked.2.2, suffix010_state]

def suffix008 : List CsrExecutableAttempt := chunk008 ++ suffix009
theorem suffix008_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1792
      counters008 suffix008 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk008 suffix009 1792 1824 counters008 counters009
    chunk008_checked.1 (congrArg (Nat.add 1792) chunk008_checked.2.1)
    chunk008_checked.2.2 suffix009_checked
theorem suffix008_length : suffix008.length = 256 := by
  rw [suffix008, List.length_append, chunk008_checked.2.1, suffix009_length]
theorem suffix008_state : advanceCsrCounters counters008 suffix008 = counters016 := by
  rw [suffix008, advanceCsrCounters_append, chunk008_checked.2.2, suffix009_state]

def suffix007 : List CsrExecutableAttempt := chunk007 ++ suffix008
theorem suffix007_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1760
      counters007 suffix007 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk007 suffix008 1760 1792 counters007 counters008
    chunk007_checked.1 (congrArg (Nat.add 1760) chunk007_checked.2.1)
    chunk007_checked.2.2 suffix008_checked
theorem suffix007_length : suffix007.length = 288 := by
  rw [suffix007, List.length_append, chunk007_checked.2.1, suffix008_length]
theorem suffix007_state : advanceCsrCounters counters007 suffix007 = counters016 := by
  rw [suffix007, advanceCsrCounters_append, chunk007_checked.2.2, suffix008_state]

def suffix006 : List CsrExecutableAttempt := chunk006 ++ suffix007
theorem suffix006_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1728
      counters006 suffix006 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk006 suffix007 1728 1760 counters006 counters007
    chunk006_checked.1 (congrArg (Nat.add 1728) chunk006_checked.2.1)
    chunk006_checked.2.2 suffix007_checked
theorem suffix006_length : suffix006.length = 320 := by
  rw [suffix006, List.length_append, chunk006_checked.2.1, suffix007_length]
theorem suffix006_state : advanceCsrCounters counters006 suffix006 = counters016 := by
  rw [suffix006, advanceCsrCounters_append, chunk006_checked.2.2, suffix007_state]

def suffix005 : List CsrExecutableAttempt := chunk005 ++ suffix006
theorem suffix005_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1696
      counters005 suffix005 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk005 suffix006 1696 1728 counters005 counters006
    chunk005_checked.1 (congrArg (Nat.add 1696) chunk005_checked.2.1)
    chunk005_checked.2.2 suffix006_checked
theorem suffix005_length : suffix005.length = 352 := by
  rw [suffix005, List.length_append, chunk005_checked.2.1, suffix006_length]
theorem suffix005_state : advanceCsrCounters counters005 suffix005 = counters016 := by
  rw [suffix005, advanceCsrCounters_append, chunk005_checked.2.2, suffix006_state]

def suffix004 : List CsrExecutableAttempt := chunk004 ++ suffix005
theorem suffix004_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1664
      counters004 suffix004 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk004 suffix005 1664 1696 counters004 counters005
    chunk004_checked.1 (congrArg (Nat.add 1664) chunk004_checked.2.1)
    chunk004_checked.2.2 suffix005_checked
theorem suffix004_length : suffix004.length = 384 := by
  rw [suffix004, List.length_append, chunk004_checked.2.1, suffix005_length]
theorem suffix004_state : advanceCsrCounters counters004 suffix004 = counters016 := by
  rw [suffix004, advanceCsrCounters_append, chunk004_checked.2.2, suffix005_state]

def suffix003 : List CsrExecutableAttempt := chunk003 ++ suffix004
theorem suffix003_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1632
      counters003 suffix003 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk003 suffix004 1632 1664 counters003 counters004
    chunk003_checked.1 (congrArg (Nat.add 1632) chunk003_checked.2.1)
    chunk003_checked.2.2 suffix004_checked
theorem suffix003_length : suffix003.length = 416 := by
  rw [suffix003, List.length_append, chunk003_checked.2.1, suffix004_length]
theorem suffix003_state : advanceCsrCounters counters003 suffix003 = counters016 := by
  rw [suffix003, advanceCsrCounters_append, chunk003_checked.2.2, suffix004_state]

def suffix002 : List CsrExecutableAttempt := chunk002 ++ suffix003
theorem suffix002_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1600
      counters002 suffix002 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk002 suffix003 1600 1632 counters002 counters003
    chunk002_checked.1 (congrArg (Nat.add 1600) chunk002_checked.2.1)
    chunk002_checked.2.2 suffix003_checked
theorem suffix002_length : suffix002.length = 448 := by
  rw [suffix002, List.length_append, chunk002_checked.2.1, suffix003_length]
theorem suffix002_state : advanceCsrCounters counters002 suffix002 = counters016 := by
  rw [suffix002, advanceCsrCounters_append, chunk002_checked.2.2, suffix003_state]

def suffix001 : List CsrExecutableAttempt := chunk001 ++ suffix002
theorem suffix001_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1568
      counters001 suffix001 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk001 suffix002 1568 1600 counters001 counters002
    chunk001_checked.1 (congrArg (Nat.add 1568) chunk001_checked.2.1)
    chunk001_checked.2.2 suffix002_checked
theorem suffix001_length : suffix001.length = 480 := by
  rw [suffix001, List.length_append, chunk001_checked.2.1, suffix002_length]
theorem suffix001_state : advanceCsrCounters counters001 suffix001 = counters016 := by
  rw [suffix001, advanceCsrCounters_append, chunk001_checked.2.2, suffix002_state]

def suffix000 : List CsrExecutableAttempt := chunk000 ++ suffix001
theorem suffix000_checked :
    checkCsrFrom 565 exactLinearCsrCompilerFamilies 1536
      counters000 suffix000 = true := by
  exact checkCsrChunk_append 565 exactLinearCsrCompilerFamilies
    chunk000 suffix001 1536 1568 counters000 counters001
    chunk000_checked.1 (congrArg (Nat.add 1536) chunk000_checked.2.1)
    chunk000_checked.2.2 suffix001_checked
theorem suffix000_length : suffix000.length = 512 := by
  rw [suffix000, List.length_append, chunk000_checked.2.1, suffix001_length]
theorem suffix000_state : advanceCsrCounters counters000 suffix000 = counters016 := by
  rw [suffix000, advanceCsrCounters_append, chunk000_checked.2.2, suffix001_state]

def chunkList : List (List CsrExecutableAttempt) := [chunk000, chunk001, chunk002, chunk003, chunk004, chunk005, chunk006, chunk007, chunk008, chunk009, chunk010, chunk011, chunk012, chunk013, chunk014, chunk015]
theorem suffix_eq_flatten_chunks : suffix000 = chunkList.flatten := by
  simp only [chunkList, suffix000, suffix001, suffix002, suffix003, suffix004, suffix005, suffix006, suffix007, suffix008, suffix009, suffix010, suffix011, suffix012, suffix013, suffix014, suffix015, suffix016, List.flatten_cons, List.flatten_nil, List.append_nil]

end HegemonCrypto.SmallWood.V8Smz9ProgramCanonicalityCsr03
