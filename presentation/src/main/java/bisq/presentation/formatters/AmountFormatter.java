/*
 * This file is part of Bisq.
 *
 * Bisq is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at
 * your option) any later version.
 *
 * Bisq is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with Bisq. If not, see <http://www.gnu.org/licenses/>.
 */

package bisq.presentation.formatters;

import bisq.common.locale.LocaleRepository;
import bisq.common.monetary.Monetary;
import bisq.common.util.DecimalFormatters;
import lombok.extern.slf4j.Slf4j;

import java.util.Locale;
import java.util.Optional;

@Slf4j
public class AmountFormatter {
    public static String formatAmountWithMinAmount(Monetary amount, Optional<Long> optionalMinAmount, boolean useMinPrecision) {
        return AmountFormatter.formatMinAmount(optionalMinAmount, amount, useMinPrecision) +
                AmountFormatter.formatAmount(amount, useMinPrecision);
    }

    public static String formatAmountWithCode(Monetary amount) {
        return formatAmountWithCode(amount, LocaleRepository.getDefaultLocale(), false);
    }

    public static String formatAmountWithCode(Monetary amount, boolean useMinPrecision) {
        return formatAmountWithCode(amount, LocaleRepository.getDefaultLocale(), useMinPrecision);
    }

    public static String formatAmountWithCode(Monetary amount, Locale locale, boolean useMinPrecision) {
        return formatAmount(amount, locale, useMinPrecision) + " " + amount.getCode();
    }

    public static String formatAmount(Monetary amount) {
        return formatAmount(amount, LocaleRepository.getDefaultLocale(), false);
    }

    public static String formatAmount(Monetary amount, boolean useMinPrecision) {
        return formatAmount(amount, LocaleRepository.getDefaultLocale(), useMinPrecision);
    }

    public static String formatAmount(Monetary amount, Locale locale) {
        return getDecimalFormat(amount, locale, false).format(amount.asDouble());
    }

    public static String formatAmount(Monetary amount, Locale locale, boolean useMinPrecision) {
        return getDecimalFormat(amount, locale, useMinPrecision).format(amount.asDouble());
    }

    public static String formatMinAmount(Optional<Long> optionalMinAmount, Monetary amount, boolean useMinPrecision) {
        return formatMinAmount(optionalMinAmount, amount, LocaleRepository.getDefaultLocale(), useMinPrecision);
    }

    public static String formatMinAmount(Optional<Long> optionalMinAmount, Monetary amount, Locale locale, boolean useMinPrecision) {
        return optionalMinAmount
                .map(minAmount -> getDecimalFormat(amount, locale, useMinPrecision).format(amount.toDouble(minAmount)) + " - ")
                .orElse("");
    }

    private static DecimalFormatters.Format getDecimalFormat(Monetary amount, Locale locale, boolean useMinPrecision) {
        return useMinPrecision ?
                DecimalFormatters.getDecimalFormat(locale, amount.getMinPrecision()) :
                DecimalFormatters.getDecimalFormat(locale, amount.getPrecision());
    }
}
